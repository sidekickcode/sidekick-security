var sidekickAnalyser = require("sidekick-analyser");
var bluebird = require('bluebird');

var path = require('path');
var assert = require("assert");

var BLACKLIST = require('./patterns/blacklist.json');

if(require.main === module) {
  execute();
}
module.exports = exports = execute;

/**
 * Entry function for every analyser. Use sidekickAnalyser to provide input and output functions.
 */
function execute() {
  sidekickAnalyser(function(setup) {
    exports.run(setup.filePath).then(function(results){
      console.log(JSON.stringify({ meta: results }));
    });
  });
}

module.exports.run = function(filePath) {
  assert(path.isAbsolute(filePath), 'filePath must be absolute');

  return scan(filePath)
    .then(
      function(issue){
        if(issue){
          return formatAsAnnotation(issue);
        } else {
          return;
        }
      },
      function(err){
        console.error("failed to analyse");
        console.log({ error: err });
        process.exit(1);
      }
    );
};

module.exports.runCliReport = function(filePath){
  assert(path.isAbsolute(filePath), 'filePath must be absolute');

  return scan(filePath)
    .then(
      function(issues){
        sidekickAnalyser.outputCliReport(issues.cliOutput);
        return issues;
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
 * @param filePath string the file to analyse
 */
function scan(filePath){
  return new Promise(function(resolve, reject){
    var failedRule = checkBlacklist(filePath);
    if(failedRule){
      resolve({filePath: filePath, failedRule: failedRule});
    } else {
      resolve();  //file was ok
    }
  });

  function checkBlacklist(filePath){
    var ext = getExtension(filePath);
    var regexExt = '.' + ext;
    var filename = getFilename(filePath, regexExt);

    var failedRule;
    BLACKLIST.some(function(rule){
      var criteria;
      if(rule.part === 'filename'){
        criteria = filename;
      } else if(rule.part === 'extension'){
        criteria = rule.type === 'match' ? ext : regexExt;  //use .ext for regex and ext for string matches
      } else {
        criteria = filePath;
      }

      if(rule.type === 'match'){
        if(rule.pattern === criteria) {
          failedRule = rule;
          return true;
        }
      } else {
        var re = new RegExp(rule.pattern, 'i');
        if(re.test(criteria)){
          failedRule = rule;
          return true;
        }
      }
    });
    return failedRule;

    function getExtension(aPath){
      return path.extname(aPath).substr(1); //return without the .
    }
    function getFilename(aPath, ext){
      var base = path.basename(aPath, ext);
      if(base){
        return ext === '.' ? base : base + ext; //add the extention so /otr.private.key returns all
      } else {
        if(aPath.charAt(0) === '.'){
          return aPath; //works for /.bashrc
        } else {
          return aPath; //works for /someFileWithoutDot
        }
      }
    }
  }
}

function formatAsAnnotation(issue) {
  issue.location = {line: -1, col: -1}; //file level not part of content
  var data = {
    analyser: 'sidekick-security',
    location: issue.location,
    message: 'File \'' + getRelativePath(issue.filePath) + '\' failed. Reason: ' + issue.failedRule.caption,
    kind: 'security_violation'
  };
  return sidekickAnalyser.createAnnotation(data);
}

function createCliOutput(items){
  var template = sidekickAnalyser.getCliReportTemplate('Security');
  var violationStr = items.length === 1 ? 'violation' : 'violations';
  template.push(cliLine(items.length + ' security ' + violationStr + ' found.'));
  items.forEach(function(item){
    var fullReason = 'File \'' + getRelativePath(item.file.path) + '\' failed. Reason: ' + item.failedRule.caption;
    template.push(cliLine(fullReason, sidekickAnalyser.MESSAGE_TYPE.ERROR));
  });
  return template;
}

function getRelativePath(aPath){
  return path.relative(__dirname, aPath);
}

function cliLine(message, colour){
  return {"colour": colour, "message": message};
}
