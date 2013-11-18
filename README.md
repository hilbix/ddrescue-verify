ddrescue-verify
===============

Use MD5 sums to verify a ddrescue image with a partly defective drive.


Usage:
------

```bash
git clone https://github.com/hilbix/ddrescue-verify.git
cd ddrescue-verify
git submodule update --init
make
make install
```

After you created some drives image with `ddrescue /dev/drive drive.img drive.log` you do:

Create the checksum-file to verify:
```bash
ddrescue-verify drive.img drive.log > drive.verify
```

Do the verification:
```bash
ddrescue-verify /dev/drive drive.verify
```

You can chain this, of course, if you think, you need it:
```bash
ddrescue-verify drive.img drive.log | ssh remote ddrescue-verify /dev/drive -
```

For options, see
```bash
ddrescue-verify -h
```

To correct the verification errors, you can use the output as logfile for ddrescue again.


Note about MD5:
---------------

Using MD5 is not really a problem here.  MD5 is fast, well understood and completely up to the task of verifying if some data was changed on the drive due to hardware failures.  Hardware usually does not mount cryptographical attacks to data, and will not exploit the MD5 weakness by chance.


License:
--------

Parts are under GPL v2.  The main source is CLLed.

This Works is placed under the terms of the Copyright Less License,
see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.

