var assert = require('chai').assert;
var ss = require('../../sidekick-security');
var path = require('path');

describe('security analyser', function() {

  describe('scans', function () {

    before(function () {
    });

    it('finds known violation: extension match', function (done) {
      ss.run(path.join(__dirname, '/fixtures/dir_with_issues/extension/extension_match.pem'))
        .then(function (annotation) {
          console.log(annotation);
          done();
        });
    });

    it('finds known violation: extension regex', function (done) {
      ss.run(path.join(__dirname, '/fixtures/dir_with_issues/extension/extension_regex.id_rsa'))
        .then(function (annotation) {
          console.log(annotation);
          done();
        });
    });

  });
});
