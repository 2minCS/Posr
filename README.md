# Posr>
Posr> provides a minimalist method for conducting Domain, IP, and File hashes OSR on major malware analysis sites. 
 

## Demo

### Posr> multi-hash table
https://user-images.githubusercontent.com/117036131/199084309-a99c1611-5a9e-466f-a744-df58932578ac.mp4


## Commands

##  `osr` 
Allows for the processing of hashes, domains, and IPs. Can build and /or export a table from the processed results.

###### Options
    -mh : Takes a multi-hash file (SHA256)
    -sh : Takes a single hash (SHA256)
    
    -md : Takes a multi-domain file
    -sd : Takes a single domain
    
    -mi : Takes a muti-IP file
    -si : Takes a single IP
      
    -xp : Exports the table into a .txt, .html, or .svg file. (Example: -xp myfile.txt)
      
    --noprint : Prevents table from displaying on the console when exporting a file
    --print : Displays the table when exporting a file


##  `cls`
Clears console and resets cursor to the top.
###### Options
    - None
    
## `config`
Allows changes to the conf.ini

###### Options
    --noemojis : Disables emojis. Changes the conf.ini file.
    --emojis : Enables emojis. Changes the conf.ini file. Default is enabled.

## conf.ini
Posr> will check the conf.ini file first for your Hybrid Analysis and BrightCloud  keys. \
Otherwise, please place these in their respective environment variables `HA_API`,`oemid`,`deviceid`

## Current Features 

### v0.3.6
* Added more API configurations to "conf.ini" 

### v0.3.5

* Added functionality to suppress emoji's [🥺]
* Added table generation status/time taken to complete 
* Added "config" command to allow for changing of "conf.ini" file 
* Added Hybrid Analysis to query.

### v0.3.0

* Export tables to Text, HTML, or SVG
* Fix bug with table files being overwritten
* Suppress table printing when exporting
* Add "cls" command to clear the console

Please see the [TODO](https://github.com/2minCS/Posr/blob/main/TODO.md) for more.


## Bug Reports & Feature Requests

You can help by reporting bugs, suggesting features, reviewing feature specifications or just by sharing your opinion.

Use [GitHub Issues](https://github.com/2minCS/Posr/issues) for all of that.

## Contributing

1. Fork the project.
2. Create a branch for your new feature.
3. Write tests.
4. Write code to make the tests pass.
5. Submit a pull request.

All pull requests are welcome !

## License

Posr> uses the MIT license. See [LICENSE](https://github.com/2minCS/Posr/blob/main/LICENSE) for more details.
