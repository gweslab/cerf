UNUSED_TCL_DATA = ("tcl/tzdata/", "tcl/msgs/", "tk/msgs/", "tk/images/",
                   "tk/demos/")


def drop_unused_tcl_data(datas):
    return [entry for entry in datas
            if not entry[0].replace("\\", "/").startswith(UNUSED_TCL_DATA)]
