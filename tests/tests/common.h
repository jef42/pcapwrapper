#include <chrono>


//1. for each protocol have different folders with files
//2. for each protocol needs at least 2 tests
//  2.a a test which reads from a pcapfile and is sent to processor,
//        which reads the package and adds all the tests inside receivedPackage
//        add more tests regarding options for package
//  2.b a test which writes in a file and after that reads the file
//      and compares the packages if they are the same
//3. tests regarding sessions
//4. maybe tests regarding interfaces/processors(or they will be test in previous tests)

void wait_test_finished(std::chrono::milliseconds milli);

struct FinishTest {
    bool is_done() { return m_done; }
protected:
    bool m_done = false;
};