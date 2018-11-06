# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'parsec/core/gui/forms/settings_widget.ui'
#
# Created by: PyQt5 UI code generator 5.11.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_SettingsWidget(object):
    def setupUi(self, SettingsWidget):
        SettingsWidget.setObjectName("SettingsWidget")
        SettingsWidget.resize(508, 356)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding
        )
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(SettingsWidget.sizePolicy().hasHeightForWidth())
        SettingsWidget.setSizePolicy(sizePolicy)
        SettingsWidget.setStyleSheet(
            "QWidget#SettingsWidget\n"
            "{\n"
            "background-color: rgb(255, 255, 255);\n"
            "}\n"
            "\n"
            "QTabWidget::pane\n"
            "{\n"
            "border: 1px solid rgb(30, 78, 162);\n"
            "}\n"
            "\n"
            "QTabBar::tab\n"
            "{\n"
            "height: 32px;\n"
            "width: 100px;\n"
            "font-size: 14px;\n"
            "font-weight: bold;\n"
            "border-top: 1px solid rgb(30, 78, 162);\n"
            "border-left: 1px solid rgb(30, 78, 162);\n"
            "border-right: 1px solid rgb(30, 78, 162);\n"
            "padding-left: 30px;\n"
            "padding-right: 30px;\n"
            "}\n"
            "\n"
            "QTabBar::tab:selected\n"
            "{\n"
            "color: rgb(12, 65, 159);\n"
            "}\n"
            "\n"
            "QTabBar::tab:!selected\n"
            "{\n"
            "color: rgb(123, 132, 163);\n"
            "}"
        )
        self.verticalLayout = QtWidgets.QVBoxLayout(SettingsWidget)
        self.verticalLayout.setContentsMargins(10, 10, 0, 0)
        self.verticalLayout.setSpacing(5)
        self.verticalLayout.setObjectName("verticalLayout")
        self.tab_settings = QtWidgets.QTabWidget(SettingsWidget)
        self.tab_settings.setStyleSheet("")
        self.tab_settings.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.tab_settings.setIconSize(QtCore.QSize(24, 24))
        self.tab_settings.setObjectName("tab_settings")
        self.tab_app = QtWidgets.QWidget()
        self.tab_app.setObjectName("tab_app")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.tab_app)
        self.verticalLayout_2.setContentsMargins(10, 15, -1, -1)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(self.tab_app)
        self.label_2.setMinimumSize(QtCore.QSize(16, 16))
        self.label_2.setMaximumSize(QtCore.QSize(16, 16))
        self.label_2.setText("")
        self.label_2.setPixmap(QtGui.QPixmap(":/icons/images/icons/right-chevron_black.png"))
        self.label_2.setScaledContents(True)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.label = QtWidgets.QLabel(self.tab_app)
        sizePolicy = QtWidgets.QSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred
        )
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.horizontalLayout_2.addWidget(self.label)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setContentsMargins(20, -1, -1, -1)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.line_edit_mountpoint = QtWidgets.QLineEdit(self.tab_app)
        self.line_edit_mountpoint.setMinimumSize(QtCore.QSize(0, 32))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.line_edit_mountpoint.setFont(font)
        self.line_edit_mountpoint.setStyleSheet(
            "border: 1px solid rgb(30, 78, 162);\n" "padding-left: 10px;"
        )
        self.line_edit_mountpoint.setText("")
        self.line_edit_mountpoint.setReadOnly(True)
        self.line_edit_mountpoint.setObjectName("line_edit_mountpoint")
        self.horizontalLayout.addWidget(self.line_edit_mountpoint)
        self.button_choose_mountpoint = QtWidgets.QPushButton(self.tab_app)
        self.button_choose_mountpoint.setMinimumSize(QtCore.QSize(0, 32))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.button_choose_mountpoint.setFont(font)
        self.button_choose_mountpoint.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.button_choose_mountpoint.setStyleSheet(
            "background-color: rgb(45, 144, 209);\n"
            "border: 1px solid rgb(11, 56, 166);\n"
            "color: rgb(255, 255, 255);\n"
            "padding-left: 10px;\n"
            "padding-right: 10px;"
        )
        icon = QtGui.QIcon()
        icon.addPixmap(
            QtGui.QPixmap(":/icons/images/icons/edit_white.png"),
            QtGui.QIcon.Normal,
            QtGui.QIcon.Off,
        )
        self.button_choose_mountpoint.setIcon(icon)
        self.button_choose_mountpoint.setIconSize(QtCore.QSize(24, 24))
        self.button_choose_mountpoint.setObjectName("button_choose_mountpoint")
        self.horizontalLayout.addWidget(self.button_choose_mountpoint)
        self.verticalLayout_3.addLayout(self.horizontalLayout)
        self.checkbox_enable_mountpoint = QtWidgets.QCheckBox(self.tab_app)
        self.checkbox_enable_mountpoint.setTristate(False)
        self.checkbox_enable_mountpoint.setObjectName("checkbox_enable_mountpoint")
        self.verticalLayout_3.addWidget(self.checkbox_enable_mountpoint)
        self.notice_mountpoint = QtWidgets.QLabel(self.tab_app)
        self.notice_mountpoint.setObjectName("notice_mountpoint")
        self.verticalLayout_3.addWidget(self.notice_mountpoint)
        self.verticalLayout_2.addLayout(self.verticalLayout_3)
        spacerItem = QtWidgets.QSpacerItem(
            20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding
        )
        self.verticalLayout_2.addItem(spacerItem)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(
            QtGui.QPixmap(":/icons/images/icons/settings_off.png"),
            QtGui.QIcon.Selected,
            QtGui.QIcon.Off,
        )
        icon1.addPixmap(
            QtGui.QPixmap(":/icons/images/icons/settings_on.png"),
            QtGui.QIcon.Selected,
            QtGui.QIcon.On,
        )
        self.tab_settings.addTab(self.tab_app, icon1, "")
        self.tab_network = QtWidgets.QWidget()
        self.tab_network.setObjectName("tab_network")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(
            QtGui.QPixmap(":/icons/images/icons/wifi_off.png"),
            QtGui.QIcon.Selected,
            QtGui.QIcon.Off,
        )
        icon2.addPixmap(
            QtGui.QPixmap(":/icons/images/icons/wifi_on.png"), QtGui.QIcon.Selected, QtGui.QIcon.On
        )
        self.tab_settings.addTab(self.tab_network, icon2, "")
        self.verticalLayout.addWidget(self.tab_settings)

        self.retranslateUi(SettingsWidget)
        self.tab_settings.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(SettingsWidget)

    def retranslateUi(self, SettingsWidget):
        _translate = QtCore.QCoreApplication.translate
        SettingsWidget.setWindowTitle(_translate("SettingsWidget", "Form"))
        self.label.setText(_translate("SettingsWidget", "Mountpoint"))
        self.button_choose_mountpoint.setText(_translate("SettingsWidget", "Choose mountpoint"))
        self.checkbox_enable_mountpoint.setText(_translate("SettingsWidget", "Enable mountpoint"))
        self.notice_mountpoint.setText(
            _translate("SettingsWidget", "You must relogin for the mountpoint to be changed")
        )
        self.tab_settings.setTabText(
            self.tab_settings.indexOf(self.tab_app), _translate("SettingsWidget", "Global")
        )
        self.tab_settings.setTabText(
            self.tab_settings.indexOf(self.tab_network), _translate("SettingsWidget", "Network")
        )


from parsec.core.gui import resources_rc
