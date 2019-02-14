CXX := g++

CXXFLAGS := -std=c++0x

CXX_LDFLAGS := -L/usr/lib -lssl -lcrypto -pthread 

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@
	
router: router.cpp crypto.o
	$(CXX) $(CXXFLAGS) $^ -o $@ $(CXX_LDFLAGS)

clean:
	rm -f *.so *.o router SlimRouter