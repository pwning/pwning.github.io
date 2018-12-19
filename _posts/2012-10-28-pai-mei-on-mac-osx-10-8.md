---
title: Pai Mei on Mac OSX 10.8
layout: post
authors:
  - Alex Reece <awreece>
categories: []
---
## tl;dr

[Pai Mei][1] is an open source windows reverse engineering framework. At one point, it was ported to Mac OSX but the project is not very actively maintained and the current instructions are quite lacking. This post hopes to offer some guidance and reduce some of the frustration involved in installing Pai Mei on Mac OSX.

<!--more-->

## Getting the libraries

The most difficult thing was finding how to get all the packages working. First and foremost, Pai Mei was designed for a 32 bit windows libary so some trickery is required to get it to work in 64 bit mode (which is necessary, because I could not get the latest `wxPython` from Homebrew to work in 32 bit mode). I did not realize at first that there was a way to use Pai Mei in 64 bit mode, so I spent a long time attempting to find universal binaries for wxPython and MySql.

Pai Mei depends on a number of packages:

  * `mysql-python`: I installed via `pip install mysql-python`.
  * `pydasm`: I installed via `pip install pydasm`.
  * `ctypes`: I believe is included by default in Python 2.5 and higher.
  * `MySql`: I installed via `brew install mysql --universal` to have a universal binary (downloading from the MySql homepage means you will get a single architecture binary).
  * `wxPython`: I installed via `brew install wxmac --universal` and then manually symlinked it into correct location:
    ```
    # ln -s /usr/local/Cellar/wxmac/2.9.4.0/lib/python2.7/site-packages/wx /Library/Python/2.7/site-packages/wx
    # ln -s /usr/local/Cellar/wxmac/2.9.4.0/lib/python2.7/site-packages/wxPython-2.9.4.0-py2.7.egg-info /Library/Python/2.7/site-packages/wxPython-2.9.4.0-py2.7.egg-info
    ```

(I sincerely hope there is a better way, but I couldn't find one). Note: as of yet, I haven't found a way to get `wxPython` to work in 32 bit python. I'll update the post when I figure that out.</li> </ul>

## Installing Pai Mei

Pai Mei uses the [pydbg][2] library (I believe it is linked incorrectly in the repository as a git submodule). I strongly encourage you [this][3] version of pydbg instead, which is a port to 64 Mac OSX by Charlie Miller and fG. Cloning the repository and installing via instructions in the `MacOSX/README` worked fine for me. Warning: you can only use this library to debug a 32 bit process from 32 bit python and a 64 bit process from 64 bit python: to use 32 bit python, do:

```
VERSIONER_PYTHON_PREFER_32_BIT=yes /usr/bin/python
```

After installing `pydbg64`, I now had a directory tree that looked like:

```
pydbg64/
├── pydbg
└── ...
paimei/
├── pgraph
├── pida
├── pydbg
├── utils
└── ...
```

I deleted the `paimei/pydbg` directory and added a symlink to the `pydbg64/pydbg` directory, then copied the fat `libmacdll.dylib` from `pydbg64/pydbg/libmacdll.dylib` to `paimei/utils`. This left a directory that looked like this:

```
pydbg64/
├── pydbg
└── ...
paimei/
├── pgraph
├── pida
├── pydbg -> ../pydbg64/pydbg
├── utils
│   ├── libmacdll.dylib
│   └── ...
└── ...
```

We now need to install all the Pai Mei packages (`utils`, `pida`, `pgraph`) into the correct place so python can find them.

```
# ln -s /usr/local/paimei/pida /Library/Python/2.7/site-packages/pida
# ln -s /usr/local/paimei/pgraph /Library/Python/2.7/site-packages/pgraph
# ln -s /usr/local/paimei/utils /Library/Python/2.7/site-packages/utils
```

### Running Pai Mei

Before we can run Pai Mei, we must initialize the database:

```
$ python /usr/local/paimei/__setup_mysql.py localhost root rootpassword
```

Next, we have to patch a few bugs in Pai Mei (it calls a deprecated function and the MySql modal tries to helpfully destroy itself after successfully connecting to the database, but unfortunately does so before Python is completely done with it).

```
diff --git a/console/PAIMEIconsole.pyw b/console/PAIMEIconsole.pyw
index a45cbbf..0fea2ae 100644
--- a/console/PAIMEIconsole.pyw
+++ b/console/PAIMEIconsole.pyw
@@ -82,7 +82,7 @@ class PAIMEIapp (wx.App):
     '''

     def OnInit (self):
-        wx.InitAllImageHandlers()
+#        wx.InitAllImageHandlers()

         splash = PAIMEIsplash()
         splash.Show()
diff --git a/console/support/mysql_connect_dialog.py b/console/support/mysql_connect
index 2201521..b641e37 100644
--- a/console/support/mysql_connect_dialog.py
+++ b/console/support/mysql_connect_dialog.py
@@ -104,7 +104,7 @@ class mysql_connect_dialog(wx.Dialog):
         self.parent.mysql_password = password

         self.mysql_connect(host, username, password)
-        self.Destroy()
+#       self.Destroy()

     def mysql_connect (self, host, username, password):
         try:
diff --git a/utils/process_stalker.py b/utils/process_stalker.py
index 987eec9..32206e4 100644
--- a/utils/process_stalker.py
+++ b/utils/process_stalker.py
@@ -281,11 +283,15 @@ class process_stalker:
                                 continue

                         basic_blocks.append(bb.ea_start)

                 if last_dll: self.log("Setting %d breakpoints on basic blocks in %s
                 else:        self.log("Setting %d breakpoints on basic blocks in ma

-                self.pydbg.bp_set(basic_blocks, restore=self.restore)
+               for block in basic_blocks:
+                       self.pydbg.bp_set(block, restore=self.restore)
```

Now, we must make sure that python has the appropriate permisisons to monitor other processes before we can use Pai Mei. Unfortunately, this is not so easy anymore &mdash; since Snow Leopard, processes must be code signed in order to escalate privileges (a good writeup [here][4]). We could possibly patch pydbg to ask for permissions and sign it to work or disabling some system wide setting, but for now we will just run Pai Mei as root.

A last disclaimer: the process stalker uses the name of the executable to find which pida module to load. Unfortunately, it truncates the process name, striping the directory, but insists that the name matches the full path to the pida module. I managed to hard code it to just always use the first pida module, but I don't know what the correct solution is.

```
diff --git a/console/modules/_PAIMEIpstalker/ProcessListCtrl.py b/console/modules/_PAIMEIpstalker/ProcessListCtrl.py
index b37bd01..63880e3 100644
--- a/console/modules/_PAIMEIpstalker/ProcessListCtrl.py
+++ b/console/modules/_PAIMEIpstalker/ProcessListCtrl.py
@@ -166,7 +166,7 @@ class ProcessListCtrl (wx.ListCtrl, ListCtrlAutoWidthMixin, ColumnSorterMixin):
             heavy               = self.top.heavy.GetValue(),                \
             ignore_first_chance = self.top.ignore_first_chance.GetValue(),  \
             log                 = self.top.msg,                             \
-            main                = main,                                     \
+            main                = self.top.pida_modules.keys()[0],          \
             mysql               = self.top.main_frame.mysql,                \
             pida_modules        = self.top.pida_modules,                    \
             pydbg               = dbg,                                      \
```

After all this, I finally got Pai Mei (barely) working but I suspect I would have had an easier time and more fun just writing it myself 😉

 [1]: https://github.com/OpenRCE/paimei
 [2]: https://github.com/OpenRCE/pydbg
 [3]: https://github.com/gdbinit/pydbg64
 [4]: http://os-tres.net/blog/2010/02/17/mac-os-x-and-task-for-pid-mach-call/