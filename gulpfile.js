'use strict';

var gulp = require('gulp');
var bitcoreTasks = require('bitcore-build-mue');

bitcoreTasks('message');

gulp.task('default', ['lint', 'coverage']);
