var assert = require('chai').assert;

var ss = require('../../sidekick-security');

var path = require('path');

describe('security analyser', function() {

  describe('scans', function() {

    before(function() {
    });

    it('runs a security scan', function() {
      var report = ss.runCliReport(path.join(__dirname, '/fixtures/dir_with_issues'));
    });
  });
});
