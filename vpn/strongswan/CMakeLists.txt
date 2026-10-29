add_definitions(-DTRANSLATION_DOMAIN=\"plasmanetworkmanagement_strongswanui\")

pkg_check_modules(P11KIT REQUIRED IMPORTED_TARGET p11-kit-1)


add_library(plasmanetworkmanagement_strongswanui MODULE)
target_sources(plasmanetworkmanagement_strongswanui PRIVATE
   strongswan.cpp
   strongswanwidget.cpp
   strongswanauth.cpp
   pkcs11certificates.cpp
   strongswan.h
   strongswanwidget.h
   strongswanauth.h
   pkcs11certificates.h
   )
ki18n_wrap_ui(plasmanetworkmanagement_strongswanui strongswanprop.ui strongswanauth.ui)

target_link_libraries(plasmanetworkmanagement_strongswanui
    plasmanm_internal
    plasmanm_editor
    KF6::CoreAddons
    KF6::I18n
    KF6::KIOWidgets
    Qt::Network
    PkgConfig::P11KIT
)

install(TARGETS plasmanetworkmanagement_strongswanui  DESTINATION ${KDE_INSTALL_PLUGINDIR}/plasma/network/vpn)
