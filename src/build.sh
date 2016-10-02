#!/bin/bash
clear
make
valgrind --leak-check=full ./httpd `/labs/tsam15/my_port` & 

