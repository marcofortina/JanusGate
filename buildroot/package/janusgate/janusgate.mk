################################################################################
#
# janusgate
#
################################################################################

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

JANUSGATE_VERSION = 0.2.0
JANUSGATE_SITE = $(BR2_EXTERNAL_JANUSGATE_PATH)/..
JANUSGATE_SITE_METHOD = local
JANUSGATE_OVERRIDE_SRCDIR_RSYNC_EXCLUSIONS = \
	--exclude=/build \
	--exclude=/build-\* \
	--exclude=/out \
	--exclude=/.ruff_cache
JANUSGATE_LICENSE = AGPL-3.0-or-later
JANUSGATE_LICENSE_FILES = LICENSE
JANUSGATE_DEPENDENCIES = \
	host-pkgconf \
	civetweb \
	jansson \
	libcap \
	libcurl \
	libidn2 \
	libmnl \
	libnetfilter_queue \
	libseccomp \
	libsodium \
	nftables \
	openssl \
	sqlite \
	zlib
JANUSGATE_CONF_OPTS = \
	-DBUILD_TESTING=OFF \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_INSTALL_PREFIX=/usr \
	-DCMAKE_INSTALL_SYSCONFDIR=/etc \
	-DCMAKE_INSTALL_LOCALSTATEDIR=/var \
	-DCMAKE_INSTALL_RUNSTATEDIR=/run \
	-DJANUSGATE_BUILD_DOCUMENTATION=OFF \
	-DJANUSGATE_HARDENING=ON \
	-DJANUSGATE_SOURCE_COMMIT="$(JANUSGATE_SOURCE_COMMIT)" \
	-DJANUSGATE_WARNINGS_AS_ERRORS=ON

define JANUSGATE_USERS
	- -1 janusgate-control 472 - - - - JanusGate control group
	janusgate 470 janusgate 470 * /var/lib/janusgate - janusgate-control JanusGate daemon
	janusgate-web 471 janusgate-web 471 * - - janusgate-control JanusGate web service
endef

define JANUSGATE_PERMISSIONS
	/etc/janusgate d 750 root janusgate-control - - - - -
	/var/lib/janusgate d 750 janusgate janusgate - - - - -
	/var/lib/janusgate/backups d 700 janusgate janusgate - - - - -
	/var/log/janusgate d 750 janusgate janusgate - - - - -
	/usr/sbin/janusgate-web f 755 root root - - - - -
	|xattr cap_net_bind_service+ep
endef

define JANUSGATE_INSTALL_BUSYBOX_INIT
	rm -f $(TARGET_DIR)/etc/init.d/janusgate-netd \
		$(TARGET_DIR)/etc/init.d/janusgate-web \
		$(TARGET_DIR)/etc/init.d/janusgated
	$(INSTALL) -D -m 755 $(@D)/init/busybox/S15janusgate-prepare \
		$(TARGET_DIR)/etc/init.d/S15janusgate-prepare
	$(INSTALL) -D -m 755 $(@D)/init/busybox/S20janusgate-netd \
		$(TARGET_DIR)/etc/init.d/S20janusgate-netd
	$(INSTALL) -D -m 755 $(@D)/init/busybox/S30janusgated \
		$(TARGET_DIR)/etc/init.d/S30janusgated
	$(INSTALL) -D -m 755 $(@D)/init/busybox/S50janusgate-web \
		$(TARGET_DIR)/etc/init.d/S50janusgate-web
endef
JANUSGATE_POST_INSTALL_TARGET_HOOKS += JANUSGATE_INSTALL_BUSYBOX_INIT

define JANUSGATE_REMOVE_DEVELOPMENT_FILES
	rm -rf $(TARGET_DIR)/usr/include/janusgate \
		$(TARGET_DIR)/usr/lib/cmake/JanusGate \
		$(TARGET_DIR)/usr/share/janusgate/api
	rm -f $(TARGET_DIR)/usr/lib/libjanusgate-common.a
endef
JANUSGATE_POST_INSTALL_TARGET_HOOKS += JANUSGATE_REMOVE_DEVELOPMENT_FILES

$(eval $(cmake-package))
