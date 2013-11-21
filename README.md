*This is usable beta code*.  However, no promises and no guarantees!


ddrescue-verify
===============

Use MD5 sums to verify a ddrescue image with a partly defective drive.

- If you need a tool which does a binary compare of the image with the drive, skipping just the unreadable parts, this is not what you are looking for.
- If you are happy with MD5 checksums comparing the data, then this is what you want.

This approach here allows you to check, that the image was successfully transferred, without transferring it back over the wire.  Note that normal MD5 sums will fail for this, because `md5sum` will break on unreadable parts of the drive.


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
ddrescue-verify drive.img drive.log > drive.check
```

Do the verification:
```bash
ddrescue-verify /dev/drive drive.check > drive.verify
```

You can chain this, of course, if you think, you need it:
```bash
ddrescue-verify drive.img drive.log | ssh remote ddrescue-verify /dev/drive - > drive.verify
```
`drive.verify` is not able to keep all information of `drive.log`.  So make sure you do not loose `drive.log`, this is your original and stays the correct source of information!

The output `drive.verify` is suitable to be fed into `ddrescue` again to update the image with the found differences:
```
ddrescue /dev/drive drive.img drive.verify
```
Beware that `ddrescue` alters `drive.verify`, so it overwrites all the possibly interesting comments which are written into it by `ddrescue-verify`.

For all options, see
```bash
ddrescue-verify -h
```


Important:
----------

- By default, `ddrescue-verify` skips block which are less than `64 KiB`.  To change that use option `-s`, for example `-s0` to read all small areas, too.

- The checksums by default use blocks of `1 MiB`.  With this setting, `drive.verify` needs `6 MiB` for each `100 GB`  of image (rule of thumb, YMMV).


Note about MD5:
---------------

Using MD5 is not really a problem here.  MD5 is fast, well understood and completely up to the task of verifying if some data was changed on the drive due to hardware failures.  Hardware usually does not mount cryptographical attacks to data, and will not exploit the MD5 weakness by chance.


License:
--------

Parts are under GPL v2.  The main source is CLLed.

This Works is placed under the terms of the Copyright Less License,
see file COPYRIGHT.CLL.  USE AT OWN RISK, ABSOLUTELY NO WARRANTY.

