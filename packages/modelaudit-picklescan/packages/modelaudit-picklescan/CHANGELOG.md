# Changelog

## 0.1.0 (2026-04-17)


### Features

* extract standalone pickle scanner package with parity harness ([#832](https://github.com/promptfoo/modelaudit/issues/832)) ([e2986cd](https://github.com/promptfoo/modelaudit/commit/e2986cddaa592306cc10541865f011b3dc99a0ba))


### Bug Fixes

* address code quality findings ([#1038](https://github.com/promptfoo/modelaudit/issues/1038)) ([7af03cf](https://github.com/promptfoo/modelaudit/commit/7af03cf42f33f1b255eb9f9cbcaac6caccd48bc1))
* bound standalone pickle stream reads ([4d0cb84](https://github.com/promptfoo/modelaudit/commit/4d0cb84af010b4ed332ebbf17fc8bd0769fa8b6e))
* **deps:** update rust crate pyo3 to 0.28.0 ([#1006](https://github.com/promptfoo/modelaudit/issues/1006)) ([fe93b47](https://github.com/promptfoo/modelaudit/commit/fe93b47c839588b3f33cfd21f4380306ec418f2a))
* detect hidden pytorch zip pickles ([#1043](https://github.com/promptfoo/modelaudit/issues/1043)) ([19b6ebe](https://github.com/promptfoo/modelaudit/commit/19b6ebe505d2ba90f81d6284d07e111f77cbf0b5))
* flag pickle persistent ids ([#938](https://github.com/promptfoo/modelaudit/issues/938)) ([2cfba40](https://github.com/promptfoo/modelaudit/commit/2cfba403e21d53f46ba7089b655cebc564dcddaf))
* harden pickle nested bypass detection ([#1027](https://github.com/promptfoo/modelaudit/issues/1027)) ([c3a3b9d](https://github.com/promptfoo/modelaudit/commit/c3a3b9d1e4ffbd854e6003afbf6ebef1e708a619))
* harden standalone pickle scanner ([#901](https://github.com/promptfoo/modelaudit/issues/901)) ([31f7dd3](https://github.com/promptfoo/modelaudit/commit/31f7dd38c6bd77631ccdca90438312c4db2ac857))
* narrow suspicious dunder string detection ([#947](https://github.com/promptfoo/modelaudit/issues/947)) ([e866760](https://github.com/promptfoo/modelaudit/commit/e8667609d293d4391205ce4e8884fa3559030604))
* preserve picklescan stack state ([#910](https://github.com/promptfoo/modelaudit/issues/910)) ([fabac5c](https://github.com/promptfoo/modelaudit/commit/fabac5c9ead49c2ed5f8357dfa53ccdcce946527))


### Documentation

* align markdown with current repo state ([#1035](https://github.com/promptfoo/modelaudit/issues/1035)) ([690bc52](https://github.com/promptfoo/modelaudit/commit/690bc5274198eb3428db9779ada0bdc2d40702ee))
