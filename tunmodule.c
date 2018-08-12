#include <Python.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>

static PyObject *TunError; 
static int tun_alloc(const char *dev, int tap)
{
    struct ifreq ifr;
    int fd, err;
    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
        return -1;
    
    memset(&ifr, 0, sizeof(ifr));

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
    *        IFF_TAP   - TAP device  
    *
    *        IFF_NO_PI - Do not provide packet information  
    */ 
    if(tap)
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI; 
    else
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 
    if(*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if((err = ioctl(fd,TUNSETIFF, (void *) &ifr)) < 0 ){
        close(fd);
        return err;
    }
    //strcpy(dev, ifr.ifr_name);
    return fd;
}              


static PyObject *
open_tun(PyObject *self, PyObject *args)
{
    const char *name;
    int fd;

    if (!PyArg_ParseTuple(args, "s", &name))
        return NULL;
    fd = tun_alloc(name, 0);
    if (fd < 0) {
        PyErr_SetString(TunError, "open_tun failed");
        return NULL;
    }
    return PyLong_FromLong(fd);
}


static PyObject *
open_tap(PyObject *self, PyObject *args)
{
    const char *name;
    int fd;

    if (!PyArg_ParseTuple(args, "s", &name))
        return NULL;
    fd = tun_alloc(name, 1);
    if (fd < 0) {
        PyErr_SetString(TunError, "open_tap failed");
        return NULL;
    }
    return PyLong_FromLong(fd);
}

static PyMethodDef TunMethods[] = {
    {"open_tun",  open_tun, METH_VARARGS,
     "open a tun device"},
    {"open_tap",  open_tap, METH_VARARGS,
     "open a tap device"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef tunmodule = {
    PyModuleDef_HEAD_INIT,
    "tun",   /* name of module */
    "tun module", /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    TunMethods
};

PyMODINIT_FUNC
PyInit_tun(void)
{
    PyObject *m;

    m = PyModule_Create(&tunmodule);
    if (m == NULL)
        return NULL;

    TunError = PyErr_NewException("tun.error", NULL, NULL);
    Py_INCREF(TunError);
    PyModule_AddObject(m, "error", TunError);
    return m;
}
