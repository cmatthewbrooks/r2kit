
# Development

This document outlines development consistencies to keep in mind while developing code to contribute:

* Pass r2pipe objects instead of passing files and repeatedly opening pipes. The r2utils class has a method called 'get_analyzed_r2pipe_from_input'. It is helpful to use this method as early as possible.