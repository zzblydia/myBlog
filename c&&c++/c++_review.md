# some note

## 1.知识点
1) 子类带参构造函数初始化父类的private成员, 只能通过构造函数参数列表的形式, 不能通过子类构造函数调用父类构造函数.
如果子类需要在构造函数体内执行其他操作，可以在构造函数体内添加相应的逻辑，但父类的构造函数必须在初始化列表中调用.

