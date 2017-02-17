# Project Item Catalog

## How to run the application

* Save file in the root folder
* Follow the command structure :
* ```sh
    $ vagrant up                            -> Power on virtual machine
    $ vagrant ssh                           -> Log into the machine
    $ cd /vagrant/catalog                   -> Switch to catalog folder
    $ python database_setup.py              -> Create database and tables
    $ python lotsofData.py                  -> Populate them with data
    $ python run.py                         -> Run The server
    Goto : http://localhost:8080/           -> Open Website
    '''

### Udacity Course Project by Saurya Man Patel 