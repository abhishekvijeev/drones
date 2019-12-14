#ifndef __SHAPE_H
#define __SHAPE_H
#include <map>
#include <string>
using namespace std;

// base class for all shapes
class shape {
public:
   // virtual void draw()=0;
   virtual void draw(int n)=0;
   
};
// typedef to make it easier to set up our factory
typedef shape *maker_t();
// our global factory
extern map<string, maker_t *, less<string> > factory;
#endif // __SHAPE_H
