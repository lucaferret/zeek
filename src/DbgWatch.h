// $Id: DbgWatch.h 80 2004-07-14 20:15:50Z jason $

// Structures and methods for implementing watches in the Bro debugger.

#ifndef dbgwatch_h
#define dbgwatch_h

#include "Debug.h"

class DbgWatch {
public:
	DbgWatch(BroObj* var_to_watch);
	DbgWatch(Expr* expr_to_watch);
	~DbgWatch();

protected:
	BroObj* var;
	Expr* expr;
};

#endif
