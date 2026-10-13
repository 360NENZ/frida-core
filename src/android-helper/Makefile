ANDROID_API_LEVEL ?= 19
ANDROID_SDK_ROOT ?= $(shell echo ~/Android/Sdk)

android_platform := android-$(ANDROID_API_LEVEL)
android_jar := $(ANDROID_SDK_ROOT)/platforms/$(android_platform)/android.jar

helper.dex: build/runtime-helper.jar
	d8 \
		--classpath $(android_jar) \
		--output build/ \
		$<
	mv build/classes.dex $@

build/runtime-helper.jar: org/tools/bridge/Helper.java org/tools/bridge/HelperBackend.java
	javac \
		-cp .:$(android_jar) \
		-bootclasspath $(android_jar) \
		-source 1.8 \
		-target 1.8 \
		-Xlint:deprecation \
		-Xlint:unchecked \
		$^ \
		-d build/bridge/java/
	jar cfe $@ org.tools.bridge.Helper -C build/bridge/java/ .
