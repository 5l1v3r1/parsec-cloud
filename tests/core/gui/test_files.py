# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

import pathlib
import pytest
from PyQt5 import QtCore, QtWidgets

from parsec.core.local_device import save_device_with_password

from parsec.core.gui.file_items import FileType, NAME_DATA_INDEX, TYPE_DATA_INDEX


@pytest.fixture
def temp_dir(tmpdir):
    pathlib.Path(tmpdir / "dir1/dir11").mkdir(parents=True)
    pathlib.Path(tmpdir / "dir1/dir12").mkdir(parents=True)
    pathlib.Path(tmpdir / "dir2/dir21").mkdir(parents=True)
    pathlib.Path(tmpdir / "file01.txt").write_text("Content file01")
    pathlib.Path(tmpdir / "file02.txt").write_text("Content file02")
    pathlib.Path(tmpdir / "dir1/dir11" / "file.txt").write_text("Content file111")
    pathlib.Path(tmpdir / "dir2" / "file2.txt").write_text("Content file2")

    return tmpdir


@pytest.fixture
async def logged_gui(
    aqtbot, gui_factory, autoclose_dialog, core_config, alice, running_backend, monkeypatch
):
    save_device_with_password(core_config.config_dir, alice, "P@ssw0rd")

    gui = await gui_factory()
    lw = gui.test_get_login_widget()
    llw = gui.test_get_login_login_widget()

    assert llw is not None

    await aqtbot.key_clicks(llw.line_edit_password, "P@ssw0rd")

    async with aqtbot.wait_signals([lw.login_with_password_clicked, gui.logged_in]):
        await aqtbot.mouse_click(llw.button_login, QtCore.Qt.LeftButton)

    central_widget = gui.test_get_central_widget()
    assert central_widget is not None

    wk_widget = gui.test_get_workspaces_widget()
    async with aqtbot.wait_signal(wk_widget.list_success):
        pass

    add_button = central_widget.widget_taskbar.layout().itemAt(0).widget()
    assert add_button is not None

    monkeypatch.setattr(
        "parsec.core.gui.custom_widgets.TextInputDialog.get_text",
        classmethod(lambda *args, **kwargs: ("Workspace")),
    )

    async with aqtbot.wait_signals([wk_widget.create_success, wk_widget.list_success]):
        aqtbot.qtbot.mouseClick(add_button, QtCore.Qt.LeftButton)

    assert wk_widget.layout_workspaces.count() == 1
    wk_button = wk_widget.layout_workspaces.itemAt(0).widget()
    assert wk_button.name == "Workspace"

    async with aqtbot.wait_signal(wk_widget.load_workspace_clicked):
        await aqtbot.mouse_click(wk_button, QtCore.Qt.LeftButton)

    yield gui


async def create_directories(logged_gui, aqtbot, monkeypatch, dir_names):
    central_widget = logged_gui.test_get_central_widget()
    assert central_widget is not None

    w_f = logged_gui.test_get_files_widget()
    assert w_f is not None

    add_button = central_widget.widget_taskbar.layout().itemAt(3).widget()
    assert add_button is not None

    for dir_name in dir_names:
        monkeypatch.setattr(
            "parsec.core.gui.custom_widgets.TextInputDialog.get_text",
            classmethod(lambda *args, **kwargs: (dir_name)),
        )
        async with aqtbot.wait_signal(w_f.folder_create_success):
            aqtbot.qtbot.mouseClick(add_button, QtCore.Qt.LeftButton)

    async with aqtbot.wait_signal(w_f.folder_stat_success, timeout=3000):
        pass


@pytest.mark.gui
@pytest.mark.trio
async def test_list_files(aqtbot, running_backend, logged_gui):
    w_f = logged_gui.test_get_files_widget()

    assert w_f is not None
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        pass

    assert w_f.label_current_workspace.text() == "Workspace"
    assert w_f.line_edit_current_directory.text() == "/"
    assert w_f.label_role.text() == "Owner"

    central_widget = logged_gui.test_get_central_widget()
    assert central_widget is not None
    assert central_widget.widget_taskbar.layout().count() == 5

    assert w_f.table_files.rowCount() == 1
    for i in range(5):
        assert w_f.table_files.item(0, i).data(TYPE_DATA_INDEX) == FileType.ParentWorkspace


@pytest.mark.gui
@pytest.mark.trio
async def test_create_dir(aqtbot, running_backend, logged_gui, monkeypatch):
    w_f = logged_gui.test_get_files_widget()

    assert w_f is not None
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        pass
    assert w_f.table_files.rowCount() == 1

    await create_directories(logged_gui, aqtbot, monkeypatch, ["Dir1"])

    assert w_f.table_files.rowCount() == 2
    for i in range(5):
        assert w_f.table_files.item(0, i).data(TYPE_DATA_INDEX) == FileType.ParentWorkspace
        assert w_f.table_files.item(1, i).data(TYPE_DATA_INDEX) == FileType.Folder
    assert w_f.table_files.item(1, 1).text() == "Dir1"


@pytest.mark.skip("Segfaults for some reason")
@pytest.mark.gui
@pytest.mark.trio
async def test_create_dir_already_exists(
    aqtbot, running_backend, logged_gui, monkeypatch, autoclose_dialog
):
    w_f = logged_gui.test_get_files_widget()

    assert w_f is not None
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        pass
    assert w_f.table_files.rowCount() == 1

    central_widget = logged_gui.test_get_central_widget()
    assert central_widget is not None

    add_button = central_widget.widget_taskbar.layout().itemAt(3).widget()
    assert add_button is not None

    monkeypatch.setattr(
        "parsec.core.gui.custom_widgets.TextInputDialog.get_text",
        classmethod(lambda *args, **kwargs: ("Dir1")),
    )
    async with aqtbot.wait_signal(w_f.folder_create_success):
        aqtbot.qtbot.mouseClick(add_button, QtCore.Qt.LeftButton)
    async with aqtbot.wait_signals([w_f.folder_stat_success, w_f.fs_synced_qt], timeout=3000):
        pass

    assert w_f.table_files.rowCount() == 2
    assert w_f.table_files.item(1, 1).text() == "Dir1"

    async with aqtbot.wait_signal(w_f.folder_create_error):
        aqtbot.qtbot.mouseClick(add_button, QtCore.Qt.LeftButton)

    assert w_f.table_files.rowCount() == 2

    assert autoclose_dialog.dialogs == [("Error", "A folder with the same name already exists.")]


@pytest.mark.gui
@pytest.mark.trio
async def test_navigate(aqtbot, running_backend, logged_gui, monkeypatch):
    w_f = logged_gui.test_get_files_widget()

    assert w_f is not None
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        pass
    assert w_f.table_files.rowCount() == 1
    assert w_f.label_current_workspace.text() == "Workspace"
    assert w_f.line_edit_current_directory.text() == "/"
    assert w_f.label_role.text() == "Owner"

    await create_directories(logged_gui, aqtbot, monkeypatch, ["Dir1", "Dir2"])

    assert w_f.table_files.rowCount() == 3
    for i in range(5):
        assert w_f.table_files.item(0, i).data(TYPE_DATA_INDEX) == FileType.ParentWorkspace
        assert w_f.table_files.item(1, i).data(TYPE_DATA_INDEX) == FileType.Folder
        assert w_f.table_files.item(2, i).data(TYPE_DATA_INDEX) == FileType.Folder
    assert w_f.table_files.item(1, 1).text() == "Dir1"
    assert w_f.table_files.item(2, 1).text() == "Dir2"

    # Navigate to one directory
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        w_f.table_files.item_activated.emit(FileType.Folder, "Dir1")
    assert w_f.table_files.rowCount() == 1
    for i in range(5):
        assert w_f.table_files.item(0, i).data(TYPE_DATA_INDEX) == FileType.ParentFolder
    assert w_f.label_current_workspace.text() == "Workspace"
    assert w_f.line_edit_current_directory.text() == "/Dir1"
    assert w_f.label_role.text() == "Owner"

    # Navigate to the workspace root
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        w_f.table_files.item_activated.emit(FileType.ParentFolder, "Parent Folder")
    assert w_f.table_files.rowCount() == 3
    for i in range(5):
        assert w_f.table_files.item(0, i).data(TYPE_DATA_INDEX) == FileType.ParentWorkspace
        assert w_f.table_files.item(1, i).data(TYPE_DATA_INDEX) == FileType.Folder
        assert w_f.table_files.item(2, i).data(TYPE_DATA_INDEX) == FileType.Folder
    assert w_f.table_files.item(1, 1).text() == "Dir1"
    assert w_f.table_files.item(2, 1).text() == "Dir2"
    assert w_f.label_current_workspace.text() == "Workspace"
    assert w_f.line_edit_current_directory.text() == "/"
    assert w_f.label_role.text() == "Owner"

    # Navigate to workspaces list
    wk_w = logged_gui.test_get_workspaces_widget()
    async with aqtbot.wait_signal(wk_w.list_success):
        w_f.table_files.item_activated.emit(FileType.ParentWorkspace, "Parent Workspace")
    assert wk_w.isVisible() is True
    assert w_f.isVisible() is False


@pytest.mark.gui
@pytest.mark.trio
async def test_delete_dirs(aqtbot, running_backend, logged_gui, monkeypatch):
    w_f = logged_gui.test_get_files_widget()

    assert w_f is not None
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        pass
    assert w_f.table_files.rowCount() == 1

    await create_directories(logged_gui, aqtbot, monkeypatch, ["Dir1", "Dir2", "Dir3"])

    assert w_f.table_files.rowCount() == 4

    # Delete one directory first
    w_f.table_files.setRangeSelected(QtWidgets.QTableWidgetSelectionRange(1, 0, 1, 0), True)
    assert len(w_f.table_files.selected_files()) == 1
    monkeypatch.setattr(
        "parsec.core.gui.custom_widgets.QuestionDialog.ask", classmethod(lambda *args: True)
    )
    async with aqtbot.wait_signals([w_f.delete_success, w_f.folder_stat_success]):
        w_f.table_files.delete_clicked.emit()
    assert w_f.table_files.rowCount() == 3

    # Then delete two
    w_f.table_files.setRangeSelected(QtWidgets.QTableWidgetSelectionRange(1, 0, 2, 0), True)
    assert len(w_f.table_files.selected_files()) == 2
    monkeypatch.setattr(
        "parsec.core.gui.custom_widgets.QuestionDialog.ask", classmethod(lambda *args: True)
    )
    async with aqtbot.wait_signals([w_f.delete_success, w_f.folder_stat_success]):
        w_f.table_files.delete_clicked.emit()
    for i in range(w_f.table_files.rowCount()):
        print(w_f.table_files.item(i, 1).data(QtCore.Qt.UserRole))
    assert w_f.table_files.rowCount() == 1
    for i in range(5):
        assert w_f.table_files.item(0, i).data(TYPE_DATA_INDEX) == FileType.ParentWorkspace


@pytest.mark.gui
@pytest.mark.trio
async def test_rename_dirs(aqtbot, running_backend, logged_gui, monkeypatch):
    w_f = logged_gui.test_get_files_widget()

    assert w_f is not None
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        pass
    assert w_f.table_files.rowCount() == 1

    await create_directories(logged_gui, aqtbot, monkeypatch, ["Dir1", "Dir2", "Dir3"])

    assert w_f.table_files.rowCount() == 4
    # Select Dir1
    w_f.table_files.setRangeSelected(QtWidgets.QTableWidgetSelectionRange(1, 0, 1, 0), True)
    assert len(w_f.table_files.selected_files()) == 1
    monkeypatch.setattr(
        "parsec.core.gui.custom_widgets.TextInputDialog.get_text",
        classmethod(lambda *args, **kwargs: ("Abcd")),
    )
    # Rename Dir1 to Abcd
    async with aqtbot.wait_signals([w_f.rename_success, w_f.folder_stat_success]):
        w_f.table_files.rename_clicked.emit()
    assert w_f.table_files.rowCount() == 4
    item = w_f.table_files.item(1, 1)
    assert item.data(NAME_DATA_INDEX) == "Abcd"
    assert item.text() == "Abcd"

    # Select Dir2 and Dir3
    w_f.table_files.setRangeSelected(QtWidgets.QTableWidgetSelectionRange(2, 0, 3, 0), True)
    assert len(w_f.table_files.selected_files()) == 2
    monkeypatch.setattr(
        "parsec.core.gui.custom_widgets.TextInputDialog.get_text",
        classmethod(lambda *args, **kwargs: ("NewName")),
    )
    async with aqtbot.wait_signals([w_f.rename_success, w_f.folder_stat_success]):
        w_f.table_files.rename_clicked.emit()
    assert w_f.table_files.rowCount() == 4
    item = w_f.table_files.item(2, 1)
    assert item.data(NAME_DATA_INDEX) == "NewName_1"
    assert item.text() == "NewName_1"
    item = w_f.table_files.item(3, 1)
    assert item.data(NAME_DATA_INDEX) == "NewName_2"
    assert item.text() == "NewName_2"


@pytest.mark.skip("Segfaults occasionally")
@pytest.mark.gui
@pytest.mark.trio
async def test_rename_dir_already_exists(
    aqtbot, running_backend, logged_gui, monkeypatch, autoclose_dialog
):
    w_f = logged_gui.test_get_files_widget()

    assert w_f is not None
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        pass
    assert w_f.table_files.rowCount() == 1

    await create_directories(logged_gui, aqtbot, monkeypatch, ["Dir1", "Dir2"])
    assert w_f.table_files.rowCount() == 3

    async with aqtbot.wait_signal(w_f.folder_stat_success):
        w_f.table_files.item_activated.emit(FileType.Folder, "Dir2")

    await create_directories(logged_gui, aqtbot, monkeypatch, ["Dir21"])
    assert w_f.table_files.rowCount() == 2

    async with aqtbot.wait_signal(w_f.folder_stat_success):
        w_f.table_files.item_activated.emit(FileType.ParentFolder, "Parent Folder")

    w_f.table_files.setRangeSelected(QtWidgets.QTableWidgetSelectionRange(1, 0, 1, 0), True)
    assert len(w_f.table_files.selected_files()) == 1
    monkeypatch.setattr(
        "parsec.core.gui.custom_widgets.TextInputDialog.get_text",
        classmethod(lambda *args, **kwargs: ("Dir2")),
    )
    async with aqtbot.wait_signal(w_f.rename_error):
        w_f.table_files.rename_clicked.emit()
    assert w_f.table_files.item(1, 1).text() == "Dir1"
    assert w_f.table_files.rowCount() == 3
    assert autoclose_dialog.dialogs == [("Error", "Can not rename the file.")]


@pytest.mark.gui
@pytest.mark.trio
async def test_import_files(
    aqtbot, running_backend, logged_gui, monkeypatch, autoclose_dialog, temp_dir
):
    w_f = logged_gui.test_get_files_widget()

    assert w_f is not None
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        pass
    assert w_f.table_files.rowCount() == 1

    monkeypatch.setattr(
        "PyQt5.QtWidgets.QFileDialog.getOpenFileNames",
        classmethod(
            lambda *args, **kwargs: ([temp_dir / "file01.txt", temp_dir / "file02.txt"], True)
        ),
    )

    async with aqtbot.wait_signals(
        [w_f.button_import_files.clicked, w_f.import_success, w_f.folder_stat_success], timeout=3000
    ):
        await aqtbot.mouse_click(w_f.button_import_files, QtCore.Qt.LeftButton)

    assert w_f.table_files.rowCount() == 3
    assert w_f.table_files.item(1, 1).text() == "file01.txt"
    assert w_f.table_files.item(2, 1).text() == "file02.txt"


@pytest.mark.skip("Can not monkeypatch getExistingDirectory")
@pytest.mark.gui
@pytest.mark.trio
async def test_import_dir(
    aqtbot, running_backend, logged_gui, monkeypatch, autoclose_dialog, temp_dir
):
    w_f = logged_gui.test_get_files_widget()

    assert w_f is not None
    async with aqtbot.wait_signal(w_f.folder_stat_success):
        pass
    assert w_f.table_files.rowCount() == 1

    monkeypatch.setattr(
        "PyQt5.QtWidgets.QFileDialog.getExistingDirectory",
        classmethod(lambda *args, **kwargs: (temp_dir,)),
    )

    async with aqtbot.wait_signals(
        [w_f.button_import_files.clicked, w_f.import_success, w_f.folder_stat_success], timeout=3000
    ):
        await aqtbot.mouse_click(w_f.button_import_files, QtCore.Qt.LeftButton)

    assert w_f.table_files.rowCount() == 3
    assert w_f.table_files.item(1, 1).text() == "dir1"
    assert w_f.table_files.item(2, 1).text() == "dir2"