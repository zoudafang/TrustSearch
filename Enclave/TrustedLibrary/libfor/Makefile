.SUFFIXES:
#
.SUFFIXES: .cpp .o .c .h
# replace the CXX variable with a path to a C++11 compatible compiler.
# ifeq ($(INTEL), 1)
# # if you wish to use the Intel compiler, please do "make INTEL=1".
#     CXX ?= /opt/intel/bin/icpc
#     CC ?= /opt/intel/bin/icpc
# ifeq ($(DEBUG),1)
#     CFLAGS = -std=c99 -O3 -Wall -ansi -DDEBUG=1 -D_GLIBCXX_DEBUG -ggdb
# else
#     CFLAGS = -std=c99 -O2 -Wall -ansi -DNDEBUG=1 -ggdb
# endif # debug
# else #intel
# ifeq ($(DEBUG),1)
#     CFLAGS = -pedantic -ggdb -DDEBUG=1 -D_GLIBCXX_DEBUG -Wall -Wextra 
# else
#     CFLAGS = -pedantic -Wall -Wextra -O3
# endif #debug
# endif #intel


HEADERS= for.h
OBJECTS = for.o

all:  test libfor.a test_compress
	echo "please run unit tests by running ./test"

for.o: for.h for.c for-gen.c
	$(CC) $(CFLAGS) -c for.c

for: $(HEADERS) for.o
	ar rvs libfor.a for.o

# gen: gen.pl
# 	perl gen.pl > for-gen.c

test: for $(HEADERS) test.c $(OBJECTS)
	$(CC) $(CFLAGS) -o test test.c $(OBJECTS) libfor.a

# test_compress.o: for.h test_compress.cpp
# 	$(CXX) $(CFLAGS) -c test_compress.cpp

test_compress: for $(HEADERS) test_compress.cpp $(OBJECTS)
	$(CXX) $(CFLAGS) -o test_compress test_compress.cpp $(OBJECTS)

		
# benchmark: for $(HEADERS) benchmark.c
# 	$(CC) $(CFLAGS) -o benchmark benchmark.c libfor.a

clean: 
	rm -f *.o test benchmark  test_compress

.PHONY: all clean test
