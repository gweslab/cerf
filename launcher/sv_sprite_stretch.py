from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Sequence, Tuple

MIN_SIZE = 64

_TCL = r"""
namespace eval ::cerf_sv {
    variable widened
    array set widened {}
}

proc ::cerf_sv::sides {border} {
    lassign $border l t r b
    if {$t eq ""} { set t $l }
    if {$r eq ""} { set r $l }
    if {$b eq ""} { set b $t }
    return [list $l $t $r $b]
}

proc ::cerf_sv::grow {img horizontal lead trail minsize} {
    set w [image width $img]
    set h [image height $img]
    set size [expr {$horizontal ? $w : $h}]
    set center [expr {$size - $lead - $trail}]
    if {$center <= 0} { return $img }
    set copies [expr {($minsize - $lead - $trail + $center - 1) / $center}]
    if {$copies <= 1} { return $img }
    set body [expr {$center * $copies}]
    set end [expr {$lead + $center}]
    if {$horizontal} {
        set out [image create photo -width [expr {$lead + $body + $trail}] \
            -height $h]
        if {$lead > 0} { $out copy $img -from 0 0 $lead $h -to 0 0 }
        $out copy $img -from $lead 0 $end $h \
            -to $lead 0 [expr {$lead + $body}] $h
        if {$trail > 0} {
            $out copy $img -from $end 0 $w $h -to [expr {$lead + $body}] 0
        }
    } else {
        set out [image create photo -width $w \
            -height [expr {$lead + $body + $trail}]]
        if {$lead > 0} { $out copy $img -from 0 0 $w $lead -to 0 0 }
        $out copy $img -from 0 $lead $w $end \
            -to 0 $lead $w [expr {$lead + $body}]
        if {$trail > 0} {
            $out copy $img -from 0 $end $w $h -to 0 [expr {$lead + $body}]
        }
    }
    return $out
}

proc ::cerf_sv::widen {img border minsize} {
    variable widened
    lassign [::cerf_sv::sides $border] l t r b
    set key [list $img $l $t $r $b]
    if {![info exists widened($key)]} {
        set wide [::cerf_sv::grow $img 1 $l $r $minsize]
        set both [::cerf_sv::grow $wide 0 $t $b $minsize]
        if {$wide ne $img && $wide ne $both} { image delete $wide }
        set widened($key) $both
    }
    return $widened($key)
}

proc ::cerf_sv::style {args} {
    if {[lrange $args 0 1] eq {element create} && [lindex $args 3] eq "image"} {
        set name [lindex $args 2]
        set spec [lindex $args 4]
        set opts [lrange $args 5 end]
        if {[dict exists $opts -border] || $name eq "Separator.separator"} {
            set border 0
            if {[dict exists $opts -border]} {
                set border [dict get $opts -border]
            }
            set base [lindex $spec 0]
            if {![dict exists $opts -width]} {
                dict set opts -width [image width $base]
            }
            if {![dict exists $opts -height]} {
                dict set opts -height [image height $base]
            }
            set wide [list [::cerf_sv::widen $base $border @MIN@]]
            foreach {state img} [lrange $spec 1 end] {
                lappend wide $state [::cerf_sv::widen $img $border @MIN@]
            }
            set args [list element create $name image $wide {*}$opts]
        }
    }
    return [uplevel 1 [list ::cerf_sv::real_style {*}$args]]
}
""".replace("@MIN@", str(MIN_SIZE))


def source_sun_valley(root: tk.Misc, sv_tcl: Path) -> None:
    root.tk.eval(_TCL)
    root.tk.eval("rename ::ttk::style ::cerf_sv::real_style")
    root.tk.eval("rename ::cerf_sv::style ::ttk::style")
    try:
        root.tk.call("source", str(sv_tcl))
    finally:
        root.tk.eval("rename ::ttk::style {}")
        root.tk.eval("rename ::cerf_sv::real_style ::ttk::style")


def widened(root: tk.Misc, image: str,
            border: Sequence[int]) -> Tuple[str, int, int]:
    wide = str(root.tk.call("::cerf_sv::widen", image, list(border),
                            MIN_SIZE))
    return (wide, int(root.tk.call("image", "width", image)),
            int(root.tk.call("image", "height", image)))
