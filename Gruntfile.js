
module.exports = function (grunt) {
  require('load-grunt-tasks')(grunt);

  grunt.initConfig({
    babel: {
      dist: {
        files: [{
          cwd: 'src',
          src: ['**/*.js'],
          dest: 'dist',
          expand: true
        }]
      }
    },

    clean: ['./dist']
  });

  grunt.registerTask('default', ['clean', 'babel']);
};
