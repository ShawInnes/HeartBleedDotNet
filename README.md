HeartBleed DotNet
=================

Drawing on the great work of others, and the disturbingly simple PoC attack, I wanted to write a .NET implementation so that I could run the PoC against some embedded devices running IPv6 only, and in a windows environment where I couldn't (or couldn't be bothered) installing python or go.

I hope this is of use to someone else.


    DotNet OpenSSL Heartbleed PoC at https://github.com/ShawInnes/HeartBleedDotNet
    by Shaw Innes (shaw@immortal.net.au)

    Based on CVE-2014-0160 OpenSSL Heartbleed PoC at https://github.com/pakesson/heartbleed-c
    by Philip Åkesson (philip.akesson@gmail.com)

    Original Python version at http://www.exploit-db.com/exploits/32745/
    by Jared Stafford (jspenguin@jspenguin.org)
