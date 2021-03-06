# Parsec Cloud (https://parsec.cloud) Copyright (c) AGPLv3 2019 Scille SAS

from uuid import UUID

from PyQt5.QtCore import pyqtSignal, QTimer, Qt
from PyQt5.QtWidgets import QWidget, QLabel

import pendulum

from parsec.core.types import (
    WorkspaceEntry,
    FsPath,
    WorkspaceRole,
    EntryID,
    EntryName,
    BackendOrganizationFileLinkAddr,
)
from parsec.core.fs import WorkspaceFS, WorkspaceFSTimestamped, FSBackendOfflineError
from parsec.core.mountpoint.exceptions import (
    MountpointAlreadyMounted,
    MountpointConfigurationError,
    MountpointConfigurationWorkspaceFSTimestampedError,
)

from parsec.core.gui.trio_thread import (
    JobResultError,
    ThreadSafeQtSignal,
    QtToTrioJob,
    JobSchedulerNotAvailable,
)
from parsec.core.gui import desktop
from parsec.core.gui.custom_dialogs import show_error, get_text_input, ask_question
from parsec.core.gui.flow_layout import FlowLayout
from parsec.core.gui.lang import translate as _
from parsec.core.gui.workspace_button import WorkspaceButton
from parsec.core.gui.timestamped_workspace_widget import TimestampedWorkspaceWidget
from parsec.core.gui.ui.workspaces_widget import Ui_WorkspacesWidget
from parsec.core.gui.workspace_sharing_widget import WorkspaceSharingWidget


async def _get_reencryption_needs(workspace_fs):
    try:
        reenc_needs = await workspace_fs.get_reencryption_need()
    except FSBackendOfflineError as exc:
        raise JobResultError("offline") from exc
    return workspace_fs.workspace_id, reenc_needs


async def _do_workspace_create(core, workspace_name):
    try:
        workspace_name = EntryName(workspace_name)
    except ValueError:
        raise JobResultError("invalid-name")
    workspace_id = await core.user_fs.workspace_create(workspace_name)
    return workspace_id


async def _do_workspace_rename(core, workspace_id, new_name, button):
    try:
        new_name = EntryName(new_name)
    except ValueError:
        raise JobResultError("invalid-name")
    try:
        await core.user_fs.workspace_rename(workspace_id, new_name)
        return button, new_name
    except Exception as exc:
        raise JobResultError("rename-error") from exc
    else:
        try:
            await core.mountpoint_manager.unmount_workspace(workspace_id)
            await core.mountpoint_manager.mount_workspace(workspace_id)
        except MountpointAlreadyMounted:
            pass


async def _do_workspace_list(core):
    workspaces = []

    async def _add_workspacefs(workspace_fs, timestamped):
        ws_entry = workspace_fs.get_workspace_entry()
        try:
            users_roles = await workspace_fs.get_user_roles()
        except FSBackendOfflineError:
            users_roles = {}
        try:
            root_info = await workspace_fs.path_info("/")
            files = root_info["children"]
        except FSBackendOfflineError:
            files = []
        workspaces.append((workspace_fs, ws_entry, users_roles, files, timestamped))

    user_manifest = core.user_fs.get_user_manifest()
    available_workspaces = [w for w in user_manifest.workspaces if w.role]
    for count, workspace in enumerate(available_workspaces):
        workspace_id = workspace.id
        workspace_fs = core.user_fs.get_workspace(workspace_id)
        await _add_workspacefs(workspace_fs, timestamped=False)
    worspaces_timestamped_dict = await core.mountpoint_manager.get_timestamped_mounted()
    for (workspace_id, timestamp), workspace_fs in worspaces_timestamped_dict.items():
        await _add_workspacefs(workspace_fs, timestamped=True)

    return workspaces


async def _do_workspace_mount(core, workspace_id, timestamp: pendulum.Pendulum = None):
    try:
        await core.mountpoint_manager.mount_workspace(workspace_id, timestamp)
    except MountpointAlreadyMounted:
        pass
    except MountpointConfigurationError as exc:
        raise JobResultError(exc)


async def _do_workspace_unmount(core, workspace_id, timestamp: pendulum.Pendulum = None):
    try:
        await core.mountpoint_manager.unmount_workspace(workspace_id, timestamp)
    except MountpointAlreadyMounted:
        pass


class WorkspacesWidget(QWidget, Ui_WorkspacesWidget):
    fs_updated_qt = pyqtSignal(str, UUID)
    fs_synced_qt = pyqtSignal(str, UUID)
    entry_downsynced_qt = pyqtSignal(UUID, UUID)

    sharing_updated_qt = pyqtSignal(WorkspaceEntry, object)
    _workspace_created_qt = pyqtSignal(WorkspaceEntry)
    load_workspace_clicked = pyqtSignal(WorkspaceFS, FsPath, bool)
    workspace_reencryption_success = pyqtSignal(QtToTrioJob)
    workspace_reencryption_error = pyqtSignal(QtToTrioJob)
    workspace_reencryption_progress = pyqtSignal(EntryID, int, int)
    workspace_mounted = pyqtSignal(QtToTrioJob)
    workspace_unmounted = pyqtSignal(QtToTrioJob)

    rename_success = pyqtSignal(QtToTrioJob)
    rename_error = pyqtSignal(QtToTrioJob)
    create_success = pyqtSignal(QtToTrioJob)
    create_error = pyqtSignal(QtToTrioJob)
    list_success = pyqtSignal(QtToTrioJob)
    list_error = pyqtSignal(QtToTrioJob)
    mount_success = pyqtSignal(QtToTrioJob)
    mount_error = pyqtSignal(QtToTrioJob)
    reencryption_needs_success = pyqtSignal(QtToTrioJob)
    reencryption_needs_error = pyqtSignal(QtToTrioJob)

    def __init__(self, core, jobs_ctx, event_bus, **kwargs):
        super().__init__(**kwargs)
        self.setupUi(self)

        self.core = core
        self.jobs_ctx = jobs_ctx
        self.event_bus = event_bus
        self.reencrypting = set()

        self.layout_workspaces = FlowLayout(spacing=40)
        self.layout_content.addLayout(self.layout_workspaces)

        self.button_add_workspace.clicked.connect(self.create_workspace_clicked)
        self.button_goto_file.clicked.connect(self.goto_file_clicked)

        self.button_add_workspace.apply_style()
        self.button_goto_file.apply_style()

        self.fs_updated_qt.connect(self._on_fs_updated_qt)
        self.fs_synced_qt.connect(self._on_fs_synced_qt)
        self.entry_downsynced_qt.connect(self._on_entry_downsynced_qt)

        self.line_edit_search.textChanged.connect(self.on_workspace_filter)

        self.rename_success.connect(self.on_rename_success)
        self.rename_error.connect(self.on_rename_error)
        self.create_success.connect(self.on_create_success)
        self.create_error.connect(self.on_create_error)
        self.list_success.connect(self.on_list_success)
        self.list_error.connect(self.on_list_error)
        self.reencryption_needs_success.connect(self.on_reencryption_needs_success)
        self.reencryption_needs_error.connect(self.on_reencryption_needs_error)
        self.workspace_reencryption_progress.connect(self._on_workspace_reencryption_progress)
        self.workspace_mounted.connect(self._on_workspace_mounted)
        self.workspace_unmounted.connect(self._on_workspace_unmounted)
        self.workspace_reencryption_success.connect(self._on_workspace_reencryption_success)
        self.workspace_reencryption_error.connect(self._on_workspace_reencryption_error)

        self.reset_timer = QTimer()
        self.reset_timer.setInterval(1000)
        self.reset_timer.setSingleShot(True)
        self.reset_timer.timeout.connect(self.list_workspaces)

        self.sharing_updated_qt.connect(self._on_sharing_updated_qt)

        self._workspace_created_qt.connect(self._on_workspace_created_qt)

    def disconnect_all(self):
        pass

    def showEvent(self, event):
        self.event_bus.connect("fs.workspace.created", self._on_workspace_created_trio)
        self.event_bus.connect("fs.entry.updated", self._on_fs_entry_updated_trio)
        self.event_bus.connect("fs.entry.synced", self._on_fs_entry_synced_trio)
        self.event_bus.connect("sharing.updated", self._on_sharing_updated_trio)
        self.event_bus.connect("fs.entry.downsynced", self._on_entry_downsynced_trio)
        self.reset()

    def hideEvent(self, event):
        try:
            self.event_bus.disconnect("fs.workspace.created", self._on_workspace_created_trio)
            self.event_bus.disconnect("fs.entry.updated", self._on_fs_entry_updated_trio)
            self.event_bus.disconnect("fs.entry.synced", self._on_fs_entry_synced_trio)
            self.event_bus.disconnect("sharing.updated", self._on_sharing_updated_trio)
            self.event_bus.disconnect("fs.entry.downsynced", self._on_entry_downsynced_trio)
        except ValueError:
            pass

    def goto_file_clicked(self):
        file_link = get_text_input(
            self,
            _("TEXT_WORKSPACE_GOTO_FILE_LINK_TITLE"),
            _("TEXT_WORKSPACE_GOTO_FILE_LINK_INSTRUCTIONS"),
            placeholder=_("TEXT_WORKSPACE_GOTO_FILE_LINK_PLACEHOLDER"),
            default_text="",
            button_text=_("ACTION_GOTO_FILE_LINK"),
        )
        if not file_link:
            return

        url = None
        try:
            url = BackendOrganizationFileLinkAddr.from_url(file_link)
        except ValueError as exc:
            show_error(self, _("TEXT_WORKSPACE_GOTO_FILE_LINK_INVALID_LINK"), exception=exc)
            return

        for item in self.layout_workspaces.items:
            w = item.widget()
            if w and w.workspace_fs.workspace_id == url.workspace_id:
                self.load_workspace(w.workspace_fs, path=url.path, selected=True)
                return
        show_error(self, _("TEXT_WORKSPACE_GOTO_FILE_LINK_WORKSPACE_NOT_FOUND"))

    def on_workspace_filter(self, pattern):
        pattern = pattern.lower()
        for i in range(self.layout_workspaces.count()):
            item = self.layout_workspaces.itemAt(i)
            if item:
                w = item.widget()
                if pattern and pattern not in w.name.lower():
                    w.hide()
                else:
                    w.show()

    def load_workspace(self, workspace_fs, path=FsPath("/"), selected=False):
        self.load_workspace_clicked.emit(workspace_fs, path, selected)

    def on_create_success(self, job):
        pass

    def on_create_error(self, job):
        if job.status == "invalid-name":
            show_error(self, _("TEXT_WORKSPACE_CREATE_NEW_INVALID_NAME"), exception=job.exc)
        else:
            show_error(self, _("TEXT_WORKSPACE_CREATE_NEW_UNKNOWN_ERROR"), exception=job.exc)

    def on_rename_success(self, job):
        workspace_button, workspace_name = job.ret
        workspace_button.reload_workspace_name(workspace_name)

    def on_rename_error(self, job):
        if job.status == "invalid-name":
            show_error(self, _("TEXT_WORKSPACE_RENAME_INVALID_NAME"), exception=job.exc)
        else:
            show_error(self, _("TEXT_WORKSPACE_RENAME_UNKNOWN_ERROR"), exception=job.exc)

    def on_list_success(self, job):
        self.layout_workspaces.clear()
        workspaces = job.ret

        if not workspaces:
            self.line_edit_search.hide()
            label = QLabel(_("TEXT_WORKSPACE_NO_WORKSPACES"))
            label.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
            self.layout_workspaces.addWidget(label)
            return

        self.line_edit_search.show()
        for count, workspace in enumerate(workspaces):
            workspace_fs, ws_entry, users_roles, files, timestamped = workspace

            try:
                self.add_workspace(
                    workspace_fs, ws_entry, users_roles, files, timestamped=timestamped
                )
            except JobSchedulerNotAvailable:
                pass

    def on_list_error(self, job):
        self.layout_workspaces.clear()
        label = QLabel(_("TEXT_WORKSPACE_NO_WORKSPACES"))
        label.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self.layout_workspaces.addWidget(label)

    def on_mount_success(self, job):
        pass

    def on_mount_error(self, job):
        if isinstance(job.status, MountpointConfigurationWorkspaceFSTimestampedError):
            show_error(self, _("TEXT_WORKSPACE_CANNOT_MOUNT"), exception=job.exc)

    def on_reencryption_needs_success(self, job):
        workspace_id, reencryption_needs = job.ret
        for idx in range(self.layout_workspaces.count()):
            widget = self.layout_workspaces.itemAt(idx).widget()
            if widget.workspace_fs.workspace_id == workspace_id:
                widget.reencryption_needs = reencryption_needs
                break

    def on_reencryption_needs_error(self, job):
        pass

    def add_workspace(self, workspace_fs, ws_entry, users_roles, files, timestamped):

        # The Qt thread should never hit the core directly.
        # Synchronous calls can run directly in the job system
        # as they won't block the Qt loop for long
        workspace_name = self.jobs_ctx.run_sync(workspace_fs.get_workspace_name)
        button = WorkspaceButton(
            workspace_name=workspace_name,
            workspace_fs=workspace_fs,
            is_shared=len(users_roles) > 1,
            is_creator=ws_entry.role == WorkspaceRole.OWNER,
            files=files[:4],
            timestamped=timestamped,
        )
        self.layout_workspaces.addWidget(button)
        button.clicked.connect(self.load_workspace)
        button.share_clicked.connect(self.share_workspace)
        button.reencrypt_clicked.connect(self.reencrypt_workspace)
        button.delete_clicked.connect(self.delete_workspace)
        button.rename_clicked.connect(self.rename_workspace)
        button.remount_ts_clicked.connect(self.remount_workspace_ts)
        button.open_clicked.connect(self.open_workspace)
        self.jobs_ctx.submit_job(
            ThreadSafeQtSignal(self, "mount_success", QtToTrioJob),
            ThreadSafeQtSignal(self, "mount_error", QtToTrioJob),
            _do_workspace_mount,
            core=self.core,
            workspace_id=workspace_fs.workspace_id,
        )
        self.jobs_ctx.submit_job(
            ThreadSafeQtSignal(self, "reencryption_needs_success", QtToTrioJob),
            ThreadSafeQtSignal(self, "reencryption_needs_error", QtToTrioJob),
            _get_reencryption_needs,
            workspace_fs=workspace_fs,
        )

    def open_workspace(self, workspace_fs):
        self.open_workspace_file(workspace_fs, None)

    def open_workspace_file(self, workspace_fs, file_name):
        file_name = FsPath("/", file_name) if file_name else FsPath("/")

        # The Qt thread should never hit the core directly.
        # Synchronous calls can run directly in the job system
        # as they won't block the Qt loop for long
        path = self.jobs_ctx.run_sync(
            self.core.mountpoint_manager.get_path_in_mountpoint,
            workspace_fs.workspace_id,
            file_name,
            workspace_fs.timestamp if isinstance(workspace_fs, WorkspaceFSTimestamped) else None,
        )

        desktop.open_file(str(path))

    def remount_workspace_ts(self, workspace_fs):
        date, time = TimestampedWorkspaceWidget.exec_modal(
            workspace_fs=workspace_fs, jobs_ctx=self.jobs_ctx, parent=self
        )

        if not date or not time:
            return

        datetime = pendulum.datetime(
            date.year(),
            date.month(),
            date.day(),
            time.hour(),
            time.minute(),
            time.second(),
            tzinfo="local",
        )
        self.mount_workspace_timestamped(workspace_fs, datetime)

    def mount_workspace_timestamped(self, workspace_fs, timestamp):
        self.jobs_ctx.submit_job(
            ThreadSafeQtSignal(self, "workspace_mounted", QtToTrioJob),
            ThreadSafeQtSignal(self, "mount_error", QtToTrioJob),
            _do_workspace_mount,
            core=self.core,
            workspace_id=workspace_fs.workspace_id,
            timestamp=timestamp,
        )

    def delete_workspace(self, workspace_fs):
        if isinstance(workspace_fs, WorkspaceFSTimestamped):
            self.jobs_ctx.submit_job(
                ThreadSafeQtSignal(self, "workspace_unmounted", QtToTrioJob),
                ThreadSafeQtSignal(self, "mount_error", QtToTrioJob),
                _do_workspace_unmount,
                core=self.core,
                workspace_id=workspace_fs.workspace_id,
                timestamp=workspace_fs.timestamp,
            )
            return
        else:
            workspace_name = self.jobs_ctx.run_sync(workspace_fs.get_workspace_name)
            result = ask_question(
                self,
                _("TEXT_WORKSPACE_DELETE_TITLE"),
                _("TEXT_WORKSPACE_DELETE_INSTRUCTIONS_workspace").format(workspace=workspace_name),
                [_("ACTION_DELETE_WORKSPACE_CONFIRM"), _("ACTION_CANCEL")],
            )
            if result != _("ACTION_DELETE_WORKSPACE_CONFIRM"):
                return
            # Workspace deletion is not available yet (button should be hidden anyway)

    def rename_workspace(self, workspace_button):
        new_name = get_text_input(
            self,
            _("TEXT_WORKSPACE_RENAME_TITLE"),
            _("TEXT_WORKSPACE_RENAME_INSTRUCTIONS"),
            placeholder=_("TEXT_WORKSPACE_RENAME_PLACEHOLDER"),
            default_text=workspace_button.name,
            button_text=_("ACTION_WORKSPACE_RENAME_CONFIRM"),
        )
        if not new_name:
            return
        self.jobs_ctx.submit_job(
            ThreadSafeQtSignal(self, "rename_success", QtToTrioJob),
            ThreadSafeQtSignal(self, "rename_error", QtToTrioJob),
            _do_workspace_rename,
            core=self.core,
            workspace_id=workspace_button.workspace_fs.workspace_id,
            new_name=new_name,
            button=workspace_button,
        )

    def share_workspace(self, workspace_fs):
        WorkspaceSharingWidget.exec_modal(
            user_fs=self.core.user_fs,
            workspace_fs=workspace_fs,
            core=self.core,
            jobs_ctx=self.jobs_ctx,
            parent=self,
        )
        self.reset()

    def reencrypt_workspace(self, workspace_id, user_revoked, role_revoked):
        if workspace_id in self.reencrypting or (not user_revoked and not role_revoked):
            return

        question = ""
        if user_revoked:
            question += "{}\n".format(_("TEXT_WORKSPACE_NEED_REENCRYPTION_BECAUSE_USER_REVOKED"))
        if role_revoked:
            question += "{}\n".format(_("TEXT_WORKSPACE_NEED_REENCRYPTION_BECAUSE_USER_REMOVED"))
        question += _("TEXT_WORKSPACE_NEED_REENCRYPTION_INSTRUCTIONS")

        r = ask_question(
            self,
            _("TEXT_WORKSPACE_NEED_REENCRYPTION_TITLE"),
            question,
            [_("ACTION_WORKSPACE_REENCRYPTION_CONFIRM"), _("ACTION_CANCEL")],
        )
        if r != _("ACTION_WORKSPACE_REENCRYPTION_CONFIRM"):
            return

        async def _reencrypt(on_progress, workspace_id):
            job = await self.core.user_fs.workspace_start_reencryption(workspace_id)
            while True:
                total, done = await job.do_one_batch(size=1)
                on_progress.emit(workspace_id, total, done)
                if total == done:
                    break
            return workspace_id

        self.reencrypting.add(workspace_id)

        self.jobs_ctx.submit_job(
            ThreadSafeQtSignal(self, "workspace_reencryption_success", QtToTrioJob),
            ThreadSafeQtSignal(self, "workspace_reencryption_error", QtToTrioJob),
            _reencrypt,
            on_progress=ThreadSafeQtSignal(
                self, "workspace_reencryption_progress", EntryID, int, int
            ),
            workspace_id=workspace_id,
        )

    def _on_workspace_reencryption_success(self, job):
        workspace_id = job.ret
        self.reencrypting.remove(workspace_id)

    def _on_workspace_reencryption_error(self, job):
        workspace_id = job.ret
        self.reencrypting.remove(workspace_id)

    def _on_workspace_reencryption_progress(self, workspace_id, total, done):
        for idx in range(self.layout_workspaces.count()):
            widget = self.layout_workspaces.itemAt(idx).widget()
            if widget.workspace_fs.workspace_id == workspace_id:
                if done == total:
                    widget.reencrypting = None
                else:
                    widget.reencrypting = (total, done)
                break

    def create_workspace_clicked(self):
        workspace_name = get_text_input(
            parent=self,
            title=_("TEXT_WORKSPACE_NEW_TITLE"),
            message=_("TEXT_WORKSPACE_NEW_INSTRUCTIONS"),
            placeholder=_("TEXT_WORKSPACE_NEW_PLACEHOLDER"),
            button_text=_("ACTION_WORKSPACE_NEW_CREATE"),
        )
        if not workspace_name:
            return
        self.jobs_ctx.submit_job(
            ThreadSafeQtSignal(self, "create_success", QtToTrioJob),
            ThreadSafeQtSignal(self, "create_error", QtToTrioJob),
            _do_workspace_create,
            core=self.core,
            workspace_name=workspace_name,
        )

    def reset(self):
        if not self.reset_timer.isActive():
            self.reset_timer.start()
            self.list_workspaces()

    def list_workspaces(self):
        self.jobs_ctx.submit_job(
            ThreadSafeQtSignal(self, "list_success", QtToTrioJob),
            ThreadSafeQtSignal(self, "list_error", QtToTrioJob),
            _do_workspace_list,
            core=self.core,
        )

    def _on_sharing_updated_trio(self, event, new_entry, previous_entry):
        self.sharing_updated_qt.emit(new_entry, previous_entry)

    def _on_sharing_updated_qt(self, new_entry, previous_entry):
        self.reset()

    def _on_workspace_created_trio(self, event, new_entry):
        self._workspace_created_qt.emit(new_entry)

    def _on_workspace_created_qt(self, workspace_entry):
        self.reset()

    def _on_fs_entry_synced_trio(self, event, id, workspace_id=None):
        self.fs_synced_qt.emit(event, id)

    def _on_fs_entry_updated_trio(self, event, workspace_id=None, id=None):
        if workspace_id and not id:
            self.fs_updated_qt.emit(event, workspace_id)

    def _on_entry_downsynced_trio(self, event, workspace_id=None, id=None):
        self.entry_downsynced_qt.emit(workspace_id, id)

    def _on_entry_downsynced_qt(self, workspace_id, id):
        self.reset()

    def _on_fs_synced_qt(self, event, id):
        self.reset()

    def _on_fs_updated_qt(self, event, workspace_id):
        self.reset()

    def _on_workspace_mounted(self, job):
        self.reset()

    def _on_workspace_unmounted(self, job):
        self.reset()
