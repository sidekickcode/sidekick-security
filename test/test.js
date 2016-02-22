var assert = require('chai').assert;
var ss = require('../../sidekick-security');
var path = require('path');

describe('security analyser', function() {

  describe('scans files', function () {

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
  
  describe('finds know issues in filenames', function(){

    function runTest (testData, done){
      testData.forEach(function(filePath){
        ss.run(path.join(__dirname, '/', filePath))
          .then(function (annotation) {
            if(annotation){
              console.log(annotation);
            } else {
              console.log('failed to find issue with: ' + filePath);
              assert.fail();
            }
          });
      });
      done();
    }

    it('detects private keys', function(done) {
      var testData = [
        'id_rsa',
        'production_rsa',
        '.ssh/id_rsa',
        'ssh/id_rsa',
        'privatekeys/id_rsa',
        'id_dsa',
        'key_dsa',
        '.ssh/id_dsa',
        'privatekeys/id_dsa',
        'id_ed25519',
        'user_ed25519',
        '.ssh/id_ed25519',
        'privatekeys/id_ed25519',
        '.ssh/id_ecdsa',
        'id_ecdsa',
        'jenkins_ecdsa',
        'ssh/id_ecdsa',
        'privatekeys/id_ecdsa'
      ];
      runTest(testData, done);
    });

    it('detects files with .pem extension', function(done) {
      var testData = [
        'privatekey.pem',
        'keys/privatekey.pem',
        '.secret.pem'
      ];
      runTest(testData, done);
    });

    it('detects files with .key(pair) extension', function(done) {
      var testData = [
        'privatekey.key',
        'keys/privatekey.key',
        '.secret.key',
        'production.keypair',
        'keys/privatekey.keypair'
      ];
      runTest(testData, done);
    });

    it('detects files with .pkcs12 extension', function(done) {
      var testData = [
        'privatekey.pkcs12',
        'keys/privatekey.pkcs12',
        '.secret.pkcs12',
      ];
      runTest(testData, done);
    });

    it('detects files with .pfx extension', function(done) {
      var testData = [
        'privatekey.pfx',
        'keys/privatekey.pfx',
        '.secret.pfx',
      ];
      runTest(testData, done);
    });

    it('detects files with .p12 extension', function(done) {
      var testData = [
        'privatekey.p12',
        'keys/privatekey.p12',
        '.secret.p12',
      ];
      runTest(testData, done);
    });

    it('detects files with .asc extension', function(done) {
      var testData = [
        'privatekey.asc',
        'keys/privatekey.asc',
        '.secret.asc',
      ];
      runTest(testData, done);
    });

    it('detects Pidgin private OTR keys', function(done) {
      var testData = [
        'otr.private_key',
        '.purple/otr.private_key',
        'pidgin/otr.private_key',
      ];
      runTest(testData, done);
    });

    it('detects shell command history files', function(done) {
      var testData = [
        '.bash_history',
        'bash_history',
        'bash/bash_history',
        '.zsh_history',
        'zsh_history',
        'zsh/zsh_history',
        '.zhistory',
        'zhistory',
        'zsh/zhistory',
        '.history',
        'history',
        'shell/history'
      ];
      runTest(testData, done);
    });

    it('detects MySQL client command history files', function(done) {
      var testData = [
        '.mysql_history',
        'mysql_history',
        'history/.mysql_history',
      ];
      runTest(testData, done);
    });

    it('detects PostgreSQL client command history files', function(done) {
      var testData = [
        '.psql_history',
        'psql_history',
        'history/.psql_history',
      ];
      runTest(testData, done);
    });

    it('detects IRB console history files', function(done) {
      var testData = [
        '.irb_history',
        'irb_history',
        'history/.irb_history',
      ];
      runTest(testData, done);
    });

    it('detects Pidgin chat client account configuration files', function(done) {
      var testData = [
        '.purple/accounts.xml',
        'purple/accounts.xml',
        'config/purple/accounts.xml',
      ];
      runTest(testData, done);
    });

    it('detects XChat client server list configuration files', function(done) {
      var testData = [
        '.xchat2/servlist_.conf',
        '.xchat2/servlist.conf',
        'xchat2/servlist_.conf',
        'xchat2/servlist.conf',
        'xchat/servlist_.conf',
        'xchat/servlist.conf',
        '.xchat/servlist_.conf',
        '.xchat/servlist.conf',
        'config/.xchat/servlist.conf'
      ];
      runTest(testData, done);
    });

    it('detects Hexchat client server list configuration files', function(done) {
      var testData = [
        '.hexchat/servlist.conf',
        'hexchat/servlist.conf',
        'config/.hexchat/servlist.conf'
      ];
      runTest(testData, done);
    });

    it('detects irrsi IRC client configuration files', function(done) {
      var testData = [
        '.irssi/config',
        'irssi/config',
        'config/.irssi/config'
      ];
      runTest(testData, done);
    });

    it('detects Recon-ng API key databases', function(done) {
      var testData = [
        '.recon-ng/keys.db',
        'recon-ng/keys.db',
        'config/.recon-ng/keys.db'
      ];
      runTest(testData, done);
    });

    it('detects DBeaver configuration files', function(done) {
      var testData = [
        '.dbeaver-data-sources.xml',
        'dbeaver-data-sources.xml',
        'config/.dbeaver-data-sources.xml'
      ];
      runTest(testData, done);
    });

    it('detects Mutt configuration files', function(done) {
      var testData = [
        '.muttrc',
        'muttrc',
        'config/.muttrc'
      ];
      runTest(testData, done);
    });

    it('detects S3cmd configuration files', function(done) {
      var testData = [
        '.s3cfg',
        's3cfg',
        'config/.s3cfg'
      ];
      runTest(testData, done);
    });

    it('detects T Twitter client configuration files', function(done) {
      var testData = [
        '.trc',
        'trc',
        'config/.trc'
      ];
      runTest(testData, done);
    });

    it('detects OpenVPN configuration files', function(done) {
      var testData = [
        'vpn.ovpn',
        '.cryptostorm.ovpn',
        'config/work.ovpn'
      ];
      runTest(testData, done);
    });

    it('detects Gitrob configuration files', function(done) {
      var testData = [
        '.gitrobrc',
        'gitrobrc',
        'config/.gitrobrc'
      ];
      runTest(testData, done);
    });

    it('detects shell configuration files', function(done) {
      var testData = [
        '.bashrc',
        'bashrc',
        'bash/.bashrc',
        '.zshrc',
        'zshrc',
        'zsh/.zshrc'
      ];
      runTest(testData, done);
    });

    it('detects shell profile files', function(done) {
      var testData = [
        '.bash_profile',
        'bash_profile',
        'bash/.bash_profile',
        '.zsh_profile',
        'zsh_profile',
        'zsh/.zsh_profile',
        '.profile',
        'profile',
        'sh/.profile'
      ];
      runTest(testData, done);
    });

    it('detects shell alias files', function(done) {
      var testData = [
        '.bash_aliases',
        'bash_aliases',
        'bash/.bash_aliases',
        '.zsh_aliases',
        'zsh_aliases',
        'zsh/.zsh_aliases',
        '.aliases',
        'aliases',
        'sh/.aliases'
      ];
      runTest(testData, done);
    });

    it('detects Rails secret token configuration files', function(done) {
      var testData = [
        'secret_token.rb',
        'config/initializers/secret_token.rb'
      ];
      runTest(testData, done);
    });

    it('detects Omniauth configuration files', function(done) {
      var testData = [
        'omniauth.rb',
        'config/initializers/omniauth.rb'
      ];
      runTest(testData, done);
    });

    it('detects Carrierwave configuration files', function(done) {
      var testData = [
        'carrierwave.rb',
        'config/initializers/carrierwave.rb'
      ];
      runTest(testData, done);
    });

    it('detects Rails schema files', function(done) {
      var testData = [
        'schema.rb',
        'db/schema.rb'
      ];
      runTest(testData, done);
    });

    it('detects Rails database configuration files', function(done) {
      var testData = [
        'database.yml',
        'config/database.yml'
      ];
      runTest(testData, done);
    });

    it('detects Django settings files', function(done) {
      var testData = [
        'settings.py',
      ];
      runTest(testData, done);
    });

    it('detects PHP configuration files', function(done) {
      var testData = [
        'config.php',
        'config/config.inc.php',
        'db_config.php',
        'secret_config.inc.php'
      ];
      runTest(testData, done);
    });

    it('detects KeePass database files', function(done) {
      var testData = [
        'keepass.kdb',
        'secret/pwd.kdb'
      ];
      runTest(testData, done);
    });

    it('detects 1Password database files', function(done) {
      var testData = [
        'passwords.agilekeychain',
        'secret/pwd.agilekeychain'
      ];
      runTest(testData, done);
    });

    it('detects Apple keychain database files', function(done) {
      var testData = [
        'passwords.keychain',
        'secret/pwd.keychain'
      ];
      runTest(testData, done);
    });

    it('detects GNOME keyring database files', function(done) {
      var testData = [
        'passwords.keystore',
        'passwords.keyring',
        'secret/pwd.keystore',
        'secret/pwd.keyring'
      ];
      runTest(testData, done);
    });

    it('detects log files', function(done) {
      var testData = [
        'log.log',
        'logs/production.log',
        '.secret.log'
      ];
      runTest(testData, done);
    });

    it('detects PCAP files', function(done) {
      var testData = [
        'capture.pcap',
        'debug/production.pcap'
      ];
      runTest(testData, done);
    });

    it('detects SQL files', function(done) {
      var testData = [
        'db.sql',
        'db.sqldump',
        'setup/database.sql',
        'backup/production.sqldump'
      ];
      runTest(testData, done);
    });

    it('detects GnuCash database files', function(done) {
      var testData = [
        'budget.gnucash',
        '.budget.gnucash',
        'finance/budget.gnucash'
      ];
      runTest(testData, done);
    });

    it('detects files containing word: backup', function(done) {
      var testData = [
        'backup.tar.gz',
        'backups/dbbackup.zip'
      ];
      runTest(testData, done);
    });

    it('detects files containing word: dump', function(done) {
      var testData = [
        'dump.bin',
        'debug/memdump.txt'
      ];
      runTest(testData, done);
    });

    it('detects files containing word: password', function(done) {
      var testData = [
        'passwords.xls',
        'private/password-reminders.txt'
      ];
      runTest(testData, done);
    });

    it('detects files containing wordis: private, key', function(done) {
      var testData = [
        'privatekey.asc',
        'super_private_key.asc',
        'private/private_keys.tar.gz'
      ];
      runTest(testData, done);
    });

    it('detects Jenkins publish over ssh plugin configuration files', function(done) {
      var testData = [
        'jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml',
        'jenkins/jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml'
      ];
      runTest(testData, done);
    });

    it('detects Jenkins credentials files', function(done) {
      var testData = [
        'credentials.xml',
        'jenkins/credentials.xml'
      ];
      runTest(testData, done);
    });

    it('detects Apache htpasswd files', function(done) {
      var testData = [
        '.htpasswd',
        'htpasswd',
        'public/htpasswd',
        'admin/.htpasswd'
      ];
      runTest(testData, done);
    });

    it('detects netrc files', function(done) {
      var testData = [
        '.netrc',
        'netrc',
        'dotfiles/.netrc',
        'homefolder/netrc'
      ];
      runTest(testData, done);
    });

    it('detects KDE Wallet Manager files', function(done) {
      var testData = [
        'wallet.kwallet',
        '.wallet.kwallet',
        'dotfiles/secret.kwallet',
        'homefolder/creds.kwallet'
      ];
      runTest(testData, done);
    });

    it('detects MediaWiki configuration files', function(done) {
      var testData = [
        'LocalSettings.php',
        'mediawiki/LocalSettings.php',
        'configs/LocalSettings.php'
      ];
      runTest(testData, done);
    });

    it('detects Tunnelblick VPN configuration files', function(done) {
      var testData = [
        'vpn.tblk',
        'secret/tunnel.tblk',
        'configs/.tunnelblick.tblk'
      ];
      runTest(testData, done);
    });

    it('detects Rubygems credentials files', function(done) {
      var testData = [
        '.gem/credentials',
        'gem/credentials',
      ];
      runTest(testData, done);
    });
  })
});
