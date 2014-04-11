How to Enroll Battle.net Mobile Authenticator

    $ bundle install
    $ ruby enroll.rb

The `enroll.rb` script will output a provisioning URL which can be converted into QR code to be scanned by various OTP apps. The script will also generate a OTP code every 30 seconds to be used for the initial setup process on Battle.net website.

### Disclaimer

The enrolment algorithm (BMA enrolment API, etc.) is a shameless rip off of [WinAuth](https://code.google.com/p/winauth). All I did was porting it to Ruby plus some other housekeeping stuff. So ... that.
