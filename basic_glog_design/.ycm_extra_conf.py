import os
import ycm_core

home_dir = os.environ['HOME']

flags = [
'-Wall',
'-Wextra',
'-Werror',
'-Wno-long-long',
'-Wno-variadic-macros',
'-fexceptions',
'-DNDEBUG',
'-std=c++11',
'-x',
'c++',
'-I',
'/usr/include',
'-isystem',
os.path.join(home_dir, '/mine/Project/Log_Design/basic_glog_design/include'),
'-isystem',
'/usr/src/linux-headers-5.4.0-151-generic/include/',
'-isystem',
'/usr/src/linux-headers-5.4.0-149/include/linux/'
'-isystem',
'/usr/lib/gcc/x86_64-linux-gnu/9/include'
]



def FlagsForFile(filename, **kwargs):
    print('Processing file:', filename)
    print('Current working directory:', os.getcwd())
    print('Flags:', flags)
    return {
        'flags': flags,
        'do_cache': True
    }
