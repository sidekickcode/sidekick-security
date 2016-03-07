"use strict";

const sidekickAnalyser = require("sidekick-analyser");

const fs = require('fs');
const path = require('path');
const assert = require("assert");

const bluebird = require('bluebird');

const BLACKLIST = require('./patterns/blacklist.json');

const LOG_FILE =  path.join(__dirname, '/debug.log');
const annotationDefaults = {analyserName: 'sidekick-security'};

//log to file as any stdout will be reported to the analyser runner
function logger(message) {
  fs.appendFile(LOG_FILE, message + '\n');
}

if(require.main === module) {
  execute();
}
module.exports = exports = execute;

/**
 * Entry function for every analyser. Use sidekickAnalyser to provide input function.
 */
function execute() {
  sidekickAnalyser(function(setup) {
    var absFilePath = path.join(setup.path, '/', setup.filePath); //append filename to the root (repo path)
    assert(path.isAbsolute(absFilePath), 'filePath must be absolute');

    run(absFilePath, setup.filePath)
      .then(function(results){
        console.log(JSON.stringify({ meta: results }));
      });
  });
}

module.exports._testRun = run;
function run(absFilePath, relFilePath) {
  return scan(absFilePath, relFilePath)
    .then(function(issue){
      var results = [];
      if(issue){
        results.push(format(issue));  //only issue per file
      }
      return results;
    },
    function(err){
      console.error("failed to analyse");
      console.log({ error: err });
      process.exit(1);
    });
}

/**
 * Perform security scan
 * @param absFilePath string the absolute path of the file to analyse
 * @param relFilePath string the relative path of the file to analyse
 * (used in reporting, e.g. "/keys/sk.id_rsa failed security check!")
 */
function scan(absFilePath, relFilePath){
  return new Promise(function(resolve, reject){
    var failedRule = checkBlacklist(absFilePath); //MUST be the absolute file path for the fs checks
    if(failedRule){
      resolve({filePath: relFilePath, failedRule: failedRule}); //report the relative file path
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

function format(issue) {
  const location = {startLine: -1, startCol: -1, endLine: -1, endCol: -1}; //file level not part of content

  return {
    analyser: annotationDefaults.analyserName,
    location: location,
    message: `File '${issue.filePath}' failed. Reason: ${issue.failedRule.caption}`,
    kind: issue.failedRule.caption,
  };
}
