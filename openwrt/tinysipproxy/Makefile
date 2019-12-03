include $(TOPDIR)/rules.mk

PKG_NAME:=tinysipproxy
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=../..

include $(INCLUDE_DIR)/package.mk

define Package/tinysipproxy
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Tiny SIP Proxy
  DEPENDS:=+sudo
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp $(SOURCE_DIR)/Makefile $(SOURCE_DIR)/$(PKG_NAME).c $(PKG_BUILD_DIR)
	$(Build/Patch)
endef

define Build/Patch
	$(SED) 's/"ping /"sudo ping /' $(PKG_BUILD_DIR)/$(PKG_NAME).c
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) CC=$(TARGET_CC) CFLAGS="$(TARGET_CFLAGS)" LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/tinysipproxy/install
	$(INSTALL_DIR) $(1)/etc/sudoers.d
	$(CP) files/$(PKG_NAME)_ping $(1)/etc/sudoers.d/
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) files/$(PKG_NAME).init $(1)/etc/init.d/$(PKG_NAME)
endef

$(eval $(call BuildPackage,tinysipproxy))
