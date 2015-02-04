ActiveDirectory
=========

A php class to query and verify users in Active Directory.

Will search on multiple domains suplied on the _forests array.

Usage
----

```php

#Checks if a user/password combination is correct, returns a boolean
ActiveDirectory::verify('<USERNAME>','<PASSWORD>');


#Gets information about a user, returns an object, or false
ActiveDirectory::getDetails('<USERNAME>','user');

#Gets information about a PC, returns an object, or false
ActiveDirectory::getDetails('<USERNAME>','cn');

```

Version
----

3.0.2

Requirements
-----------

ActiveDirectory has the following requirements:


* [PHP] - Version 5.*
* [PHP LDAP Extension]

Normal Installation
--------------
Copy to a project directory and include the class.

```sh
git clone https://github.com/rpunnett/ActiveDirectory.git ActiveDirectory
cd ActiveDirectory
cp ActiveDirectory.php <include path>
```


License
----

MIT



[robert punnett]:https://github.com/rpunnett
[PHP]:http://php.net/
[PHP LDAP Extension]:http://php.net/manual/en/book.ldap.php
