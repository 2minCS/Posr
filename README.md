# Posr>
Posr> provides a minimalist method for conducting Domain, IP, and File hashes OSR on major malware analysis sites. 


## Demo

### Posr> multi-hash table
https://user-images.githubusercontent.com/117036131/199084309-a99c1611-5a9e-466f-a744-df58932578ac.mp4


## Options

- -mh : Takes a multi-hash file (SHA256)
- -sh : Takes a single hash (SHA256)

- -md : Takes a multi-domain file
- -sd : Takes a single domain

- -mi : Takes a muti-IP file
- -si : Takes a single IP

- -xp : Exports the table into a .txt, .html, or .svg file. (Example: -xp myfile.txt)

- --noprint : Prevents table from displaying on the console when exporting a file
- --print : Displays the table when exporting a file


## Current Features 

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
