#!/usr/bin/env python3
"""Regenerate NetCrack.xcodeproj from the source tree.

The generated project is committed, so you never need to run this to build the
app. It exists so the project file stays reproducible: add or remove a Swift
file under NetCrack/ and re-run this script instead of hand-editing the
pbxproj.

    python3 Scripts/generate_project.py

Requires only the Python standard library.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "NetCrack"
PROJECT_NAME = "NetCrack"
BUNDLE_ID = "com.netcrack.app"
DEPLOYMENT_TARGET = "14.0"
SWIFT_VERSION = "5.0"  # Swift *language mode*; the toolchain itself is 5.9+

# Directories under NetCrack/ that become groups, in display order.
GROUP_ORDER = ["App", "Models", "Backend", "ViewModels", "Views", "Resources"]
SKIP_DIRS = {"Assets.xcassets"}

FILE_TYPES = {
    ".swift": ("sourcecode.swift", "sources"),
    ".plist": ("text.plist.xml", None),
    ".entitlements": ("text.plist.entitlements", None),
    ".txt": ("text", "resources"),
    ".md": ("net.daringfireball.markdown", None),
    ".xcassets": ("folder.assetcatalog", "resources"),
}


def file_type(path: Path) -> tuple[str, str | None]:
    if path.suffix == ".xcassets" or path.name.endswith(".xcassets"):
        return "folder.assetcatalog", "resources"
    return FILE_TYPES.get(path.suffix, ("text", None))


class IDAllocator:
    def __init__(self) -> None:
        self.counter = 0

    def next(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}{self.counter:022X}"


ids = IDAllocator()
build_file_ids: dict[str, str] = {}
file_ref_ids: dict[str, str] = {}
group_ids: dict[str, str] = {}


def collect() -> tuple[list[Path], list[Path]]:
    sources: list[Path] = []
    resources: list[Path] = []
    for directory in GROUP_ORDER:
        base = APP / directory
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_dir():
                continue
            if any(part in SKIP_DIRS for part in path.relative_to(APP).parts):
                continue
            _, build_phase = file_type(path)
            if build_phase == "sources":
                sources.append(path)
            elif build_phase == "resources":
                resources.append(path)

    # The asset catalogue is a folder reference, so it is added by hand: a
    # file walk would otherwise pull in every Contents.json inside it.
    for catalogue in APP.rglob("*.xcassets"):
        resources.append(catalogue)
    return sources, resources


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def main() -> None:
    sources, resources = collect()

    # Asset catalogue needs to be a single reference, not its contents.
    resource_refs = [p for p in resources if p.name.endswith(".xcassets")]
    for path in resources:
        if path.name.endswith(".xcassets"):
            continue
        resource_refs.append(path)
    resource_refs = sorted(set(resource_refs), key=lambda p: p.as_posix())

    for path in sources:
        build_file_ids[relative(path)] = ids.next("A1")
    for path in resource_refs:
        build_file_ids[relative(path)] = ids.next("B1")
    # Files that are referenced by build settings rather than a build phase;
    # they still belong in the navigator.
    extra_refs = [APP / "Resources" / "Info.plist", APP / "Resources" / "NetCrack.entitlements"]
    extra_refs = [p for p in extra_refs if p.exists()]

    for path in sources + resource_refs + extra_refs:
        file_ref_ids[relative(path)] = ids.next("C1")

    for group in ["", *GROUP_ORDER]:
        group_ids[group] = ids.next("D1")

    product_ref = ids.next("E1")
    target_id = ids.next("F1")
    project_id = ids.next("AA")
    sources_phase = ids.next("BA")
    frameworks_phase = ids.next("BB")
    resources_phase = ids.next("BC")
    project_config_list = ids.next("CA")
    target_config_list = ids.next("CB")
    project_debug = ids.next("DA")
    project_release = ids.next("DB")
    target_debug = ids.next("DC")
    target_release = ids.next("DD")

    # ---------------------------------------------------------------- groups
    group_sections: list[str] = []
    root_children = [group_ids[g] for g in GROUP_ORDER if (APP / g).exists()]
    root_children.append(product_ref)

    group_sections.append(
        "\t\t{id} /* NetCrack */ = {{\n"
        "\t\t\tisa = PBXGroup;\n"
        "\t\t\tchildren = (\n{children}\n\t\t\t);\n"
        "\t\t\tpath = NetCrack;\n"
        "\t\t\tsourceTree = \"<group>\";\n"
        "\t\t}};".format(
            id=group_ids[""],
            children="\n".join(f"\t\t\t\t{c}," for c in root_children),
        )
    )

    for group in GROUP_ORDER:
        if not (APP / group).exists():
            continue
        children = []
        base = APP / group
        # Nested groups first (Views/Components).
        for sub in sorted([d for d in base.iterdir() if d.is_dir() and not d.name.endswith(".xcassets")], key=lambda p: p.name):
            children.append((group_ids.setdefault(f"{group}/{sub.name}", ids.next("D1")), f"{sub.name}"))
        files = [
            p for p in sorted(base.iterdir())
            if not p.is_dir() and relative(p) in file_ref_ids
        ]
        asset_dirs = [p for p in sorted(base.iterdir()) if p.name.endswith(".xcassets")]
        body = []
        for sub_id, name in children:
            body.append(f"\t\t\t\t{sub_id} /* {name} */,")
        for path in files + asset_dirs:
            body.append(f"\t\t\t\t{file_ref_ids[relative(path)]} /* {path.name} */,")
        group_sections.append(
            "\t\t{id} /* {name} */ = {{\n"
            "\t\t\tisa = PBXGroup;\n"
            "\t\t\tchildren = (\n{children}\n\t\t\t);\n"
            "\t\t\tpath = {name};\n"
            "\t\t\tsourceTree = \"<group>\";\n"
            "\t\t}};".format(
                id=group_ids[group],
                name=group,
                children="\n".join(body),
            )
        )
        # Nested groups.
        for sub_id, name in children:
            sub_files = [
                f"\t\t\t\t{file_ref_ids[relative(p)]} /* {p.name} */,"
                for p in sorted((base / name).iterdir())
                if not p.is_dir() and relative(p) in file_ref_ids
            ]
            group_sections.append(
                "\t\t{id} /* {name} */ = {{\n"
                "\t\t\tisa = PBXGroup;\n"
                "\t\t\tchildren = (\n{children}\n\t\t\t);\n"
                "\t\t\tpath = {name};\n"
                "\t\t\tsourceTree = \"<group>\";\n"
                "\t\t}};".format(id=sub_id, name=name, children="\n".join(sub_files))
            )

    # ------------------------------------------------------------ file refs
    file_ref_sections: list[str] = []
    for path in sources + resource_refs + extra_refs:
        key = relative(path)
        ftype, _ = file_type(path)
        file_ref_sections.append(
            "\t\t{id} /* {name} */ = {{isa = PBXFileReference; lastKnownFileType = {ftype}; path = {name}; sourceTree = \"<group>\"; }};".format(
                id=file_ref_ids[key],
                name=path.name,
                ftype=ftype,
            )
        )
    file_ref_sections.append(
        "\t\t{id} /* NetCrack.app */ = {{isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = NetCrack.app; sourceTree = BUILT_PRODUCTS_DIR; }};".format(
            id=product_ref
        )
    )

    # ----------------------------------------------------------- build files
    build_file_sections: list[str] = []
    for path in sources:
        key = relative(path)
        build_file_sections.append(
            "\t\t{bf} /* {name} in Sources */ = {{isa = PBXBuildFile; fileRef = {fr} /* {name} */; }};".format(
                bf=build_file_ids[key], fr=file_ref_ids[key], name=path.name
            )
        )
    for path in resource_refs:
        key = relative(path)
        build_file_sections.append(
            "\t\t{bf} /* {name} in Resources */ = {{isa = PBXBuildFile; fileRef = {fr} /* {name} */; }};".format(
                bf=build_file_ids[key], fr=file_ref_ids[key], name=path.name
            )
        )

    source_entries = "\n".join(
        "\t\t\t\t{bf} /* {name} in Sources */,".format(bf=build_file_ids[relative(p)], name=p.name)
        for p in sources
    )
    resource_entries = "\n".join(
        "\t\t\t\t{bf} /* {name} in Resources */,".format(bf=build_file_ids[relative(p)], name=p.name)
        for p in resource_refs
    )

    common_settings = """\t\t\t\tALWAYS_SEARCH_USER_PATHS = NO;
\t\t\t\tCLANG_ANALYZER_NONNULL = YES;
\t\t\t\tCLANG_ENABLE_MODULES = YES;
\t\t\t\tCLANG_ENABLE_OBJC_ARC = YES;
\t\t\t\tCLANG_WARN_BOOL_CONVERSION = YES;
\t\t\t\tCLANG_WARN_UNREACHABLE_CODE = YES;
\t\t\t\tCOPY_PHASE_STRIP = NO;
\t\t\t\tENABLE_STRICT_OBJC_MSGSEND = YES;
\t\t\t\tENABLE_USER_SCRIPT_SANDBOXING = NO;
\t\t\t\tGCC_C_LANGUAGE_STANDARD = gnu17;
\t\t\t\tGCC_NO_COMMON_BLOCKS = YES;
\t\t\t\tGCC_WARN_UNDECLARED_SELECTOR = YES;
\t\t\t\tGCC_WARN_UNINITIALIZED_AUTOS = YES;
\t\t\t\tGCC_WARN_UNUSED_FUNCTION = YES;
\t\t\t\tGCC_WARN_UNUSED_VARIABLE = YES;
\t\t\t\tLOCALIZATION_PREFERS_STRING_CATALOGS = YES;
\t\t\t\tMACOSX_DEPLOYMENT_TARGET = {target};
\t\t\t\tSDKROOT = macosx;
\t\t\t\tSWIFT_STRICT_CONCURRENCY = minimal;
\t\t\t\tSWIFT_VERSION = {swift};
"""

    project_debug_settings = common_settings.format(target=DEPLOYMENT_TARGET, swift=SWIFT_VERSION) + """\t\t\t\tDEBUG_INFORMATION_FORMAT = dwarf;
\t\t\t\tENABLE_TESTABILITY = YES;
\t\t\t\tGCC_DYNAMIC_NO_PIC = NO;
\t\t\t\tGCC_OPTIMIZATION_LEVEL = 0;
\t\t\t\tGCC_PREPROCESSOR_DEFINITIONS = (
\t\t\t\t\t"DEBUG=1",
\t\t\t\t\t"$(inherited)",
\t\t\t\t);
\t\t\t\tONLY_ACTIVE_ARCH = YES;
\t\t\t\tSWIFT_ACTIVE_COMPILATION_CONDITIONS = "DEBUG $(inherited)";
\t\t\t\tSWIFT_OPTIMIZATION_LEVEL = "-Onone";
"""

    project_release_settings = common_settings.format(target=DEPLOYMENT_TARGET, swift=SWIFT_VERSION) + """\t\t\t\tDEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";
\t\t\t\tENABLE_NS_ASSERTIONS = NO;
\t\t\t\tSWIFT_COMPILATION_MODE = wholemodule;
\t\t\t\tSWIFT_OPTIMIZATION_LEVEL = "-O";
"""

    target_settings = """\t\t\t\tASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;
\t\t\t\tASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME = AccentColor;
\t\t\t\tCODE_SIGN_ENTITLEMENTS = NetCrack/Resources/NetCrack.entitlements;
\t\t\t\tCODE_SIGN_IDENTITY = "-";
\t\t\t\tCODE_SIGN_STYLE = Manual;
\t\t\t\tCOMBINE_HIDPI_IMAGES = YES;
\t\t\t\tCURRENT_PROJECT_VERSION = 1;
\t\t\t\tDEVELOPMENT_TEAM = "";
\t\t\t\tENABLE_HARDENED_RUNTIME = NO;
\t\t\t\tGENERATE_INFOPLIST_FILE = NO;
\t\t\t\tINFOPLIST_FILE = NetCrack/Resources/Info.plist;
\t\t\t\tLD_RUNPATH_SEARCH_PATHS = (
\t\t\t\t\t"$(inherited)",
\t\t\t\t\t"@executable_path/../Frameworks",
\t\t\t\t);
\t\t\t\tMARKETING_VERSION = 1.0;
\t\t\t\tPRODUCT_BUNDLE_IDENTIFIER = {bundle};
\t\t\t\tPRODUCT_NAME = "$(TARGET_NAME)";
\t\t\t\tPROVISIONING_PROFILE_SPECIFIER = "";
\t\t\t\tSWIFT_EMIT_LOC_STRINGS = YES;
\t\t\t\tSWIFT_VERSION = {swift};
""".format(bundle=BUNDLE_ID, swift=SWIFT_VERSION)

    project = """// !$*UTF8*$!
{{
\tarchiveVersion = 1;
\tclasses = {{
\t}};
\tobjectVersion = 60;
\tobjects = {{

/* Begin PBXBuildFile section */
{build_files}
/* End PBXBuildFile section */

/* Begin PBXFileReference section */
{file_refs}
/* End PBXFileReference section */

/* Begin PBXFrameworksBuildPhase section */
\t\t{frameworks} /* Frameworks */ = {{
\t\t\tisa = PBXFrameworksBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
/* End PBXFrameworksBuildPhase section */

/* Begin PBXGroup section */
{groups}
/* End PBXGroup section */

/* Begin PBXNativeTarget section */
\t\t{target} /* NetCrack */ = {{
\t\t\tisa = PBXNativeTarget;
\t\t\tbuildConfigurationList = {target_configs} /* Build configuration list for PBXNativeTarget "NetCrack" */;
\t\t\tbuildPhases = (
\t\t\t\t{sources_phase} /* Sources */,
\t\t\t\t{frameworks} /* Frameworks */,
\t\t\t\t{resources_phase} /* Resources */,
\t\t\t);
\t\t\tbuildRules = (
\t\t\t);
\t\t\tdependencies = (
\t\t\t);
\t\t\tname = NetCrack;
\t\t\tproductName = NetCrack;
\t\t\tproductReference = {product} /* NetCrack.app */;
\t\t\tproductType = "com.apple.product-type.application";
\t\t}};
/* End PBXNativeTarget section */

/* Begin PBXProject section */
\t\t{project_id} /* Project object */ = {{
\t\t\tisa = PBXProject;
\t\t\tattributes = {{
\t\t\t\tBuildIndependentTargetsInParallel = 1;
\t\t\t\tLastSwiftUpdateCheck = 1600;
\t\t\t\tLastUpgradeCheck = 1600;
\t\t\t\tTargetAttributes = {{
\t\t\t\t\t{target} = {{
\t\t\t\t\t\tCreatedOnToolsVersion = 16.0;
\t\t\t\t\t}};
\t\t\t\t}};
\t\t\t}};
\t\t\tbuildConfigurationList = {project_configs} /* Build configuration list for PBXProject "NetCrack" */;
\t\t\tcompatibilityVersion = "Xcode 15.0";
\t\t\tdevelopmentRegion = en;
\t\t\thasScannedForEncodings = 0;
\t\t\tknownRegions = (
\t\t\t\ten,
\t\t\t\tBase,
\t\t\t);
\t\t\tmainGroup = {root_group};
\t\t\tminimizedProjectReferenceProxies = 1;
\t\t\tproductRefGroup = {root_group} /* NetCrack */;
\t\t\tprojectDirPath = "";
\t\t\tprojectRoot = "";
\t\t\ttargets = (
\t\t\t\t{target} /* NetCrack */,
\t\t\t);
\t\t}};
/* End PBXProject section */

/* Begin PBXResourcesBuildPhase section */
\t\t{resources_phase} /* Resources */ = {{
\t\t\tisa = PBXResourcesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
{resource_entries}
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
/* End PBXResourcesBuildPhase section */

/* Begin PBXSourcesBuildPhase section */
\t\t{sources_phase} /* Sources */ = {{
\t\t\tisa = PBXSourcesBuildPhase;
\t\t\tbuildActionMask = 2147483647;
\t\t\tfiles = (
{source_entries}
\t\t\t);
\t\t\trunOnlyForDeploymentPostprocessing = 0;
\t\t}};
/* End PBXSourcesBuildPhase section */

/* Begin XCBuildConfiguration section */
\t\t{project_debug} /* Debug */ = {{
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {{
{project_debug_settings}\t\t\t}};
\t\t\tname = Debug;
\t\t}};
\t\t{project_release} /* Release */ = {{
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {{
{project_release_settings}\t\t\t}};
\t\t\tname = Release;
\t\t}};
\t\t{target_debug} /* Debug */ = {{
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {{
{target_settings}\t\t\t}};
\t\t\tname = Debug;
\t\t}};
\t\t{target_release} /* Release */ = {{
\t\t\tisa = XCBuildConfiguration;
\t\t\tbuildSettings = {{
{target_settings}\t\t\t}};
\t\t\tname = Release;
\t\t}};
/* End XCBuildConfiguration section */

/* Begin XCConfigurationList section */
\t\t{project_configs} /* Build configuration list for PBXProject "NetCrack" */ = {{
\t\t\tisa = XCConfigurationList;
\t\t\tbuildConfigurations = (
\t\t\t\t{project_debug} /* Debug */,
\t\t\t\t{project_release} /* Release */,
\t\t\t);
\t\t\tdefaultConfigurationIsVisible = 0;
\t\t\tdefaultConfigurationName = Release;
\t\t}};
\t\t{target_configs} /* Build configuration list for PBXNativeTarget "NetCrack" */ = {{
\t\t\tisa = XCConfigurationList;
\t\t\tbuildConfigurations = (
\t\t\t\t{target_debug} /* Debug */,
\t\t\t\t{target_release} /* Release */,
\t\t\t);
\t\t\tdefaultConfigurationIsVisible = 0;
\t\t\tdefaultConfigurationName = Release;
\t\t}};
/* End XCConfigurationList section */
\t}};
\trootObject = {project_id} /* Project object */;
}}
""".format(
        build_files="\n".join(build_file_sections),
        file_refs="\n".join(file_ref_sections),
        groups="\n".join(group_sections),
        frameworks=frameworks_phase,
        target=target_id,
        target_configs=target_config_list,
        sources_phase=sources_phase,
        resources_phase=resources_phase,
        product=product_ref,
        project_id=project_id,
        project_configs=project_config_list,
        root_group=group_ids[""],
        resource_entries=resource_entries,
        source_entries=source_entries,
        project_debug=project_debug,
        project_release=project_release,
        target_debug=target_debug,
        target_release=target_release,
        project_debug_settings=project_debug_settings,
        project_release_settings=project_release_settings,
        target_settings=target_settings,
    )

    project_dir = ROOT / "NetCrack.xcodeproj"
    project_dir.mkdir(exist_ok=True)
    (project_dir / "project.pbxproj").write_text(project, encoding="utf-8")

    # Minimal shared scheme so `xcodebuild -scheme NetCrack` works out of the
    # box without Xcode having to auto-create one.
    scheme_dir = project_dir / "xcshareddata" / "xcschemes"
    scheme_dir.mkdir(parents=True, exist_ok=True)
    scheme = """<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1600" version="1.7">
   <BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES">
      <BuildActionEntries>
         <BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">
            <BuildableReference
               BuildableIdentifier="primary"
               BlueprintIdentifier="{target}"
               BuildableName="NetCrack.app"
               BlueprintName="NetCrack"
               ReferencedContainer="container:NetCrack.xcodeproj">
            </BuildableReference>
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.DebuggerFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES">
      <Testables>
      </Testables>
   </TestAction>
   <LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.DebuggerFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES" debugServiceExtension="internal" allowLocationSimulation="YES">
      <BuildableProductRunnable runnableDebuggingMode="0">
         <BuildableReference
            BuildableIdentifier="primary"
            BlueprintIdentifier="{target}"
            BuildableName="NetCrack.app"
            BlueprintName="NetCrack"
            ReferencedContainer="container:NetCrack.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </LaunchAction>
   <ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" savedToolIdentifier="" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES">
      <BuildableProductRunnable runnableDebuggingMode="0">
         <BuildableReference
            BuildableIdentifier="primary"
            BlueprintIdentifier="{target}"
            BuildableName="NetCrack.app"
            BlueprintName="NetCrack"
            ReferencedContainer="container:NetCrack.xcodeproj">
         </BuildableReference>
      </BuildableProductRunnable>
   </ProfileAction>
   <AnalyzeAction buildConfiguration="Debug">
   </AnalyzeAction>
   <ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES">
   </ArchiveAction>
</Scheme>
""".format(target=target_id)
    (scheme_dir / "NetCrack.xcscheme").write_text(scheme, encoding="utf-8")

    print(f"Wrote {project_dir/ 'project.pbxproj'}")
    print(f"  {len(sources)} Swift sources, {len(resource_refs)} resources")


if __name__ == "__main__":
    main()
