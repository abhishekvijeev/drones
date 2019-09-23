#include <bits/stdc++.h>

using namespace std;


#define MAY_EXEC		0x00000001
#define MAY_WRITE		0x00000002
#define MAY_READ		0x00000004
#define MAY_APPEND		0x00000008

int main()
{
	while(1)
	{
		int a;
		cout << "enter a number:";
		cin >> a;
		if (a == MAY_EXEC)
			cout << "exec matched\n";
		else if(a == MAY_WRITE)
			cout << "write matched\n";

		else if(a == MAY_READ)
			cout << "read matched\n";

		else if(a == MAY_APPEND)
			cout << "append matched\n";
		else
		{
			cout << a << " " << MAY_READ << " " << MAY_WRITE << " " << MAY_APPEND << endl;
		}


	}
}
