var sidekickAnalyser = require("sidekick-analyser");
var MESSAGE_TYPE = sidekickAnalyser.MESSAGE_TYPE;
var klaw = require('klaw');
var through2 = require('through2');
var bluebird = require('bluebird');

var path = require('path');
var assert = require("assert");

var blacklist = require('./patterns/blacklist.json');

if(require.main === module) {
  execute();
}
module.exports = exports = execute;

var EXTENTION_RE = /\.([0-9a-z]+)$/i;

var BLACKLISTED_EXTENTIONS = createExtentionBlacklist(blacklist);

/**
 * Entry function for every analyser. Use sidekickAnalyser to provide input and output functions.
 */
function execute() {
  sidekickAnalyser(function(setup) {
    exports.run().then(function(results){
      console.log(JSON.stringify({ meta: results }));
    });
  });
}

module.exports.run = function(dir) {
  assert(path.isAbsolute(dir), 'dir must be absolute');
  return scan(dir)
    .then(
      function(deps){
        //return convertToAnnotations(deps, fileContent);
      },
      function(err){
        console.error("failed to analyse");
        console.log({ error: err });
        process.exit(1);
      }
    );
};

module.exports.runCliReport = function(dir){
  assert(path.isAbsolute(dir), 'dir must be absolute');
  return scan(dir)
    .then(
      function(report){
        sidekickAnalyser.outputCliReport(report.cliOutput);
        return report;
      },
      function(err){
        console.error("failed to analyse");
        console.log({ error: err });
        process.exit(1);
      }
    );
};

/**
 * Perform security scan
 * @param dir string the root directory to scan (absolute path)
 */
function scan(dir){
  var excludeDirFilter = through2.obj(function (item, enc, next) {
    if (!item.stats.isDirectory()){
      console.log('adding item: ' + JSON.stringify(item));
      this.push(item);  //add non dirs
    }
    next();
  });

  var badExtentionFinder = through2.obj(function (item, enc, next) {
    if(item.stats.isFile()){
      if(isExtentionBlacklisted(getExtention(item.path))){
        console.log('have bad file');
        this.push({item: item, reason: 'extention'});
      }
    }
    next();
  });

  var promise = new Promise(function(resolve, reject){
    var items = []; // files, directories, symlinks, etc
    console.log('Starting scan for dir: ' + dir);
    klaw(dir)
      .pipe(excludeDirFilter)
      .pipe(badExtentionFinder)
      .on('data', function (item) {
        items.push(item.path)
      })
      .on('end', function () {
        //anything in items is BAADD
        resolve(function(items){
          return items;
        });
      });
  });
  return promise;

  function getExtention(path){
    var matches = EXTENTION_RE.exec(path);
    return matches[1];  //0: pattern, 1: captured group does not include dot
  }

  function isExtentionBlacklisted(ext){
    console.log('checking extention blacklist: ' + ext);
    var found = BLACKLISTED_EXTENTIONS.indexOf(ext);
    return found !== -1;
  }
}

function createExtentionBlacklist(blacklist){
  var exts = [];
  blacklist.forEach(function(rule){
    //console.log('checking rule: ' + JSON.stringify(rule));
    if(rule.part === 'extension'){
      console.log('have extension: ' + rule.pattern);
      exts.push(rule.pattern);
    }
  });
  return exts;
}

function formatAsAnnotation(dep) {
  var data = {
    analyser: 'sidekick-david',
    location: dep.location,
    message: dep.message,
    kind: 'dependency_outdated'
  };
  return sidekickAnalyser.createAnnotation(data);
}

function cliLine(message, colour){
  return {"colour": colour, "message": message};
}
