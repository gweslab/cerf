# Core library submodules

The core parts of CERF are standalone libraries. Each library has its own
repository. The CERF repository includes each library as a git submodule at
the repository root.

Put each core library at the repository root. Put third-party code in
`external/`.

## A library stands alone

- A library builds and passes its own tests without its consumers. A consumer
  is a repository or a library that includes the library as a submodule. The
  library includes no file of a consumer, and it names no type of a consumer.
- A library declares its names in its own namespace. A consumer can define a
  global name that a library also defines. The program then breaks the
  one-definition rule, and the linker accepts it with no error. A macro that a
  consumer expands writes each library name in full, from the global
  namespace.
- A library calls no facility of a consumer, for example the log or the fatal
  path of the consumer. When a library must report a condition, it calls an
  interface that its consumer implements.
- Each library has a CMake target, its own tests and its own CI.
- A library lists the third-party components that it links and the projects that the authors studied for its code in its own `THIRD_PARTY_NOTICES.md`. The root `THIRD_PARTY_NOTICES.txt` repeats every entry of every library, because the CERF binaries contain the libraries.
- `.gitmodules` records the public HTTPS URL of each library, so a clone needs
  no SSH key.
- The project rules apply inside a library as they apply in the rest of this
  repository.
