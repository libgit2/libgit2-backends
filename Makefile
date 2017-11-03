LIBGIT2_INCLUDE_DIR = "${LIBGIT2_INCLUDE_DIR}"
LIBGIT2_LIBRARIES = "${LIBGIT2_LIBRARIES}"
export LIBGIT2_INCLUDE_DIR
export LIBGIT2_LIBRARIES

.PHONY: es

# LIBGIT2_INCLUDE_DIR=/usr/local/include/git2/ LIBGIT2_LIBRARIES= make es
es:
	-cd elasticsearch && cmake -H. -Bbuild && cmake --build build && cd ..