var assert = require('chai').assert;

var ss = require('../../sidekick-security');

var path = require('path');

describe('security analyser', function() {

  describe('scans', function() {

    before(function() {
    });

    it('runs a security scan with known violations', function() {
      ss.run(path.join(__dirname, '/fixtures/dir_with_issues/extension_match.pem'))
          .then(function(annotation){
        console.log(annotation);
      });
    });
  });
});
