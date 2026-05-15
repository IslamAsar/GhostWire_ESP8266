# GhostWire_ESP8266 Library Folder

This folder contains project-specific libraries for the GhostWire_ESP8266 project.
Each library should be placed in its own subdirectory under `lib/`.

## Folder structure

Library source directories should follow one of these structures:

```text
lib/
  <LibraryName>/
    <source files .cpp, .h>
```

## PlatformIO integration

PlatformIO compiles these libraries and links them into the final executable.
PlatformIO will discover dependent libraries automatically by scanning the project source files.

## Including a library

Use the relative path to the header, for example:

```cpp
#include "../lib/Library_Name/Library.h"
```

Replace `Library_Name` and `Library.h` with the actual library folder and header file names.

## References

- https://docs.platformio.org/page/librarymanager/ldf.html