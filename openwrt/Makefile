.EXPORT_ALL_VARIABLES:
.ONESHELL:
.SHELLFLAGS= -ec

default: all

clean:
	-$(RM) *.ipk

all:
	if [ -z "$${OPENWRT_SDK_TARBALL}" ]; then
		echo 'ERROR: $$OPENWRT_SDK_TARBALL not set' >&2
		exit 1
	fi
	temp="$$(mktemp --directory --tmpdir openwrt-build-pkg.XXXXXXXXXX)"
	trap 'rm -rf "$${temp}"' EXIT
	tar x -C "$${temp}" --strip-components=1 -f "$${OPENWRT_SDK_TARBALL}"
	export PATH="$${temp}/staging_dir/host/bin:$${PATH}"
	echo "src-link repo $$(pwd)" >"$${temp}/feeds.conf"
	"$${temp}/scripts/feeds" update repo
	"$${temp}/scripts/feeds" install -a -p repo
	make -C "$${temp}" defconfig
	for package in *; do
		if [ -f "$${package}/Makefile" ]; then
			echo "CONFIG_PACKAGE_$${package}=y" >>"$${temp}/.config"
			make -C "$${temp}" "package/$${package}/compile"
		fi
	done
	cp "$${temp}"/bin/packages/*/repo/*.ipk . || true

.PHONY: default all clean
