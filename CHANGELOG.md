### v2.1.0 -> v2.2.0

#### Features

- [`4ea46e7`](https://github.com/deis/builder/commit/4ea46e72a0b7700d94b6fbc810dbe61312aadbd9) registry: use registry proxy to talk to the internal registry

#### Fixes

- [`2a6f434`](https://github.com/deis/builder/commit/2a6f43461ece18739229aa343f9f32ab2e853281) pkg/conf: skip file if directory
- [`08a89d8`](https://github.com/deis/builder/commit/08a89d8824844b05c1e8080021aeb6834b5b77e9) pkg/conf: skip ..data symlink reading creds
- [`fe6f482`](https://github.com/deis/builder/commit/fe6f4823c9c7f167016c7ac8287b905d9933622a) pkg/git/git.go: write the pre-receive hook script directly to the file descriptor
- [`8cc816f`](https://github.com/deis/builder/commit/8cc816fdeaaecc5e3c2f5354282bcf9416f22749) sshd: re-enable TestConcurrentPushSameRepo (#361)

#### Documentation

- [`33405a7`](https://github.com/deis/builder/commit/33405a75fcb4641b3a2c965c5ce89a2fbfe21d7b) github: simplify github templates


### v2.0.0-rc2 -> v2.0.0

#### Features

- [`6fdcf08`](https://github.com/deis/builder/commit/6fdcf08064d9ac7b15115553e76c7dc3e6c31f37) lock: add timeout to repository lock feature

#### Documentation

- [`e038851`](https://github.com/deis/builder/commit/e038851678da9363a99a3639d67181abb6ab68bf) CHANGELOG.md: add entry for v2.0.0-rc2
- [`58a8786`](https://github.com/deis/builder/commit/58a8786d764db22a7f01c68398ec86aff34f6541) pkg: update help URL to https://deis.com/

#### Maintenance

- [`f6580ee`](https://github.com/deis/builder/commit/f6580ee558309f9d5902e660b2de69a0e07d776a) various: remove beta status

### v2.0.0-rc1 -> v2.0.0-rc2

#### Fixes

- [`f0dbc67`](https://github.com/deis/builder/commit/f0dbc67ebc22b6d350f62db179a51c86f6da1e15) proctype: deploy dockerfile app with procfile

### v2.0.0-beta4 -> v2.0.0-rc1

#### Features

 - [`a002c31`](https://github.com/deis/builder/commit/a002c3174aabe8aab0ca7675bc370f438919478e) probes: add controller check to the readiness probe


#### Maintenance

 - [`635b21e`](https://github.com/deis/builder/commit/635b21ed10e1353ab227dee9116e0d9f70c616ba) Dockerfile: Refactor image to use ubuntu-slim
 - [`54c14e6`](https://github.com/deis/builder/commit/54c14e6ea129c2fe68e7781849b0907ea2e6f729) packages: use github mirror for speter/inf
 - [`9f9414e`](https://github.com/deis/builder/commit/9f9414e3d01d44b7fc79a5aa732f1f56ef789656) Makefile,Dockerfile: DEIS_RELEASE -> WORKFLOW_RELEASE

### v2.0.0-beta3 -> v2.0.0-beta4

#### Features

 - [`d5bcd49`](https://github.com/deis/builder/commit/d5bcd49cd9c525067eb6f19cb0eb3e805ec9d680) controller: the error message from controller instead of response code

#### Fixes

 - [`de48920`](https://github.com/deis/builder/commit/de48920731b7d61a78a96fb1807f5e5a6caeef1b) gitreceive: ignore error if `git gc` fails
 - [`1743208`](https://github.com/deis/builder/commit/1743208e551f5deaef3bbfc82949874dc6f63cc8) cleaner: remove the usage of watch api
 - [`40d0e0c`](https://github.com/deis/builder/commit/40d0e0c8033de6fc8667a08a66e8d92848ba648e) git-push: the errors during git push

#### Documentation

 - [`adfa401`](https://github.com/deis/builder/commit/adfa4018232adf7f1b47849467a5c6ab09cf615a) badge: added code-beat badge
 - [`123110b`](https://github.com/deis/builder/commit/123110b802f8c244b87f3212f56ab5034ebdb82d) CHANGELOG.md: update for v2.0.0-beta3

### v2.0.0-beta2 -> v2.0.0-beta3

#### Features

 - [`cd32029`](https://github.com/deis/builder/commit/cd3202999bc0b265332509e9f60aee6fbd7b442f) gitreceive: remove tmp build dir on success
 - [`514d0e3`](https://github.com/deis/builder/commit/514d0e3f604de5ddb2450d0b7a5b5729325573e8) pkg/sshd: Store private keys in kubernetes secret

#### Fixes

 - [`1c37d86`](https://github.com/deis/builder/commit/1c37d86feae5925f430c2825c81abc5104cc1453) sshd: log incoming env request to debug level
 - [`cd259f8`](https://github.com/deis/builder/commit/cd259f86e547996944f6312d5e0dc2fe43c19ded) slugbuilder: check for the succeded status while waiting for slugbuilder pod
 - [`ab88b54`](https://github.com/deis/builder/commit/ab88b5412c9e7f848dc57de060f7215e8dc66e1b) bug: use the deis time which supports RFC3339 dates
 - [`7701533`](https://github.com/deis/builder/commit/7701533b0a8cb334bdf9a18547db08d6efc62ff3) .github: rename docs-v2 to workflow

#### Maintenance

 - [`2a9db63`](https://github.com/deis/builder/commit/2a9db634a43427057f783a063ea122275c18f322) .travis.yml: Deep six the travis -> jenkins webhooks

### v2.0.0-beta1 -> v2.0.0-beta2

#### Features

 - [`f278e80`](https://github.com/deis/builder/commit/f278e80952d1b53a1edcad09667e11aca1db8ab3) progress: status to avoid losing session
 - [`8df2568`](https://github.com/deis/builder/commit/8df2568ee73ad2773df986728f5e595e55b299cb) storage: remove polling for object in storage
 - [`8ede6fd`](https://github.com/deis/builder/commit/8ede6fd09f7915029d1a412bbca7b28dd418c4d1) _scripts: add CHANGELOG.md and generator script
 - [`e0d06f8`](https://github.com/deis/builder/commit/e0d06f80be09d294baccd7a312b77cc2fa2af3a6) storage: implement separate storage layer

#### Fixes

 - [`9d7f864`](https://github.com/deis/builder/commit/9d7f864b92aef98fffd373731f6467804a183f7f) pkg/git/git.go: fix blank image pull policy
 - [`b2e80d4`](https://github.com/deis/builder/commit/b2e80d4bf234d2622b02085a602b93334229f972) git,gitreceive,sshd: make builder pod image pull policies configurable
 - [`b0d8941`](https://github.com/deis/builder/commit/b0d89417dc2432c3fbf1ccd082a43527c2611d0a) cleaner: builder taking high CPU
 - [`7df5844`](https://github.com/deis/builder/commit/7df58446337404e7050278359677a48d42b62b93) makefile: make the docker-build call the build
 - [`29b827b`](https://github.com/deis/builder/commit/29b827ba6ef4e76f9d21e642f1fe5737f6b427e7) k8s_util.go: check pod condition error
 - [`a1ccc09`](https://github.com/deis/builder/commit/a1ccc09fea62934c1e07998c044a2265cadba660) pkg/gitreceive/storage/object_test.go: adjust min number of calls to the statter

### 2.0.0-alpha -> v2.0.0-beta1

#### Features

 - [`97d1d2a`](https://github.com/deis/builder/commit/97d1d2a4019a245a9b5498bc293ba1a56d3ed395) Makefile: enable immutable (git-based
 - [`ea1712f`](https://github.com/deis/builder/commit/ea1712f6c9d2cf8684acebe86dea46244e20d2d6) cleaner: write unit test for cleaner
 - [`5e2baaf`](https://github.com/deis/builder/commit/5e2baaffc965e524fb4ed03231e77c667227550c) builder: get the slug/docker builder images from the environment
 - [`6955570`](https://github.com/deis/builder/commit/69555705190db894e1aab28a5cfb2fc3c41f1264) lock: change cleaner code to listen to k8s namespsce events
 - [`1d926fa`](https://github.com/deis/builder/commit/1d926fae1128e29b71817d59f3c2d3521f855f7a) server: add more tests for the SSH server
 - [`7330a6d`](https://github.com/deis/builder/commit/7330a6de7c9639ac338cb0625318d8cc49bbff52) race: change heritage label for every pod launch
 - [`707fbea`](https://github.com/deis/builder/commit/707fbea094e02c3353d39068e211c2ea127ec99e) race: waitforpod errors out only for timeout
 - [`f51d3a2`](https://github.com/deis/builder/commit/f51d3a2fb374f12f04c45d941362c4f5c6c5ae23) storage: configure bucket name
 - [`aefc6e4`](https://github.com/deis/builder/commit/aefc6e4dd1ce1a1bb95cce7d44c1cbcf5f78fe40) storage: use single storage region variable
 - [`096fd61`](https://github.com/deis/builder/commit/096fd611ff3232365f53089700541c812d211cc8) .travis.yml: have this job notify its sister job in Jenkins
 - [`56f572e`](https://github.com/deis/builder/commit/56f572e9c4f1c975af2570449b3e9d848deaf160) storage: change outside storage settings
 - [`a6682ca`](https://github.com/deis/builder/commit/a6682cacc44a1c64eb2ee0390b085a32d7ff7580) builder: compress go binaries
 - [`7de8d2d`](https://github.com/deis/builder/commit/7de8d2d660fbde09e716e3c094b456d33f0259e2) travis: add travis webhook -> e2e tests
 - [`8738a59`](https://github.com/deis/builder/commit/8738a5927014858f987560cc7f1e373d356d2a7c) dockerbuilder: add logic to build dockerfile builds
 - [`2944714`](https://github.com/deis/builder/commit/2944714899035f7fc99f16b52ba1e1da3f570c2a) builder: make the builder pod timeout configurable
 - [`dc0c124`](https://github.com/deis/builder/commit/dc0c12436069cd20eb57b84d11f55adbfac0bbef) manifests: sync with deis-dev charts. Assumes secrets already exist from a helm install
 - [`9f99caa`](https://github.com/deis/builder/commit/9f99caae709bd0bd6f448a37e107e3707c07e545) builder: remove extra git archive tar
 - [`66539c2`](https://github.com/deis/builder/commit/66539c23cdc403a79f5a78c07f685c91b810cc54) builder: adjust dockerbuilder and slugrunner templates
 - [`b88e6ed`](https://github.com/deis/builder/commit/b88e6ed3240133d4481309a65c4feafc1a01dcd4) builder: add support for custom buildpack url

#### Fixes

 - [`fdb79a9`](https://github.com/deis/builder/commit/fdb79a9af8d64908d4cd3073a5d4a0b2f9ed4e7a) (all): add godocs and address other golint issues
 - [`b93cc16`](https://github.com/deis/builder/commit/b93cc16e4e8c2faaa911bda16a64fe71133df240) pkg: rename workflow to controller
 - [`46b3a67`](https://github.com/deis/builder/commit/46b3a6759d5f83765941d730ec2f57a82e98c098) pkg/k8s/namespace.go: run go fmt on the repo
 - [`0d49f00`](https://github.com/deis/builder/commit/0d49f006b1638431708d81f1bdf681e1e20ee679) procfile: get the procfile from the slug if not present
 - [`358933a`](https://github.com/deis/builder/commit/358933a9f1cccf5f45fb8f35c4906f110bc59840) pkg/gitreceive/storage/object_test.go: skip TestWaitForObjectMissing
 - [`e81096a`](https://github.com/deis/builder/commit/e81096ace03793653ffa0ee4d088a697f3349549) storagepoll: dont poll s3 for slugfile if app type is dockerfile
 - [`4875b97`](https://github.com/deis/builder/commit/4875b97646da3c1f961a18c790752073175d3b38) pkg/gitreceive: replace the AWS SDK with minio-go
 - [`a22473d`](https://github.com/deis/builder/commit/a22473d9140585dfd87b3dc6b42b760f6daada98) (all): creating and using interfaces for system tasks
 - [`9fa4d02`](https://github.com/deis/builder/commit/9fa4d021e0b42cf8aa234c635d3a552a76d32d6c) pkg/sshd/server_test.go: write test for gitPktLine (WIP
 - [`d0e0952`](https://github.com/deis/builder/commit/d0e09520b9735f6fdcb754cd5cfbc4ba10b2c7a8) pkg/gitreceive/build.go: change err message to indicate code for failed build pods
 - [`c377f9f`](https://github.com/deis/builder/commit/c377f9f10098e90b91e3cece691454e0a061c64e) config.go: increase builder pod wait duration
 - [`60e5c9f`](https://github.com/deis/builder/commit/60e5c9f5903cd0ea155bfae5e067916a565c7e21) pkg/sshd: demote handshake failure log to debug
 - [`071d4a2`](https://github.com/deis/builder/commit/071d4a202a2fc6abfb59078ab327e07a8700f519) timeout: reset pod tick timeout duration to 0.1s
 - [`fb744ce`](https://github.com/deis/builder/commit/fb744ceb6b069aaaacd6ac342b0f174673f707c0) boot.go,pkg/(all): implement a deleted app cleaner
 - [`210afa4`](https://github.com/deis/builder/commit/210afa455cfc269f29d578298f558e91d6e7caf4) gitreceive/storage/bucket.go: silence bucket creation errors
 - [`3d5feb3`](https://github.com/deis/builder/commit/3d5feb38c6cecd1550bee7fb16f00eddc41e7741) (all): add readiness & liveness probes
 - [`953145b`](https://github.com/deis/builder/commit/953145b7c941e51934b0152e3e6f9a568586b0a1) .travis.yml: run the docker-build target on all branches
 - [`a3ebb95`](https://github.com/deis/builder/commit/a3ebb95456fa173d3772ecaa81c080964598e4b9) builder: if exit code from build pod is not 0 it must return an error
 - [`8fd6f2d`](https://github.com/deis/builder/commit/8fd6f2df24de4eefccddbaac12ff6aa3da16a89b) pkg/gitreceive/build.go: send the entire slug URL to the controller
 - [`8b1de86`](https://github.com/deis/builder/commit/8b1de86c7ace3e822c254d7920429b706258bbef) builder: change dockerfile builder image
 - [`bc5e070`](https://github.com/deis/builder/commit/bc5e070b4dd2be1eb0899aeadf890f342508f6d6) Makefile,build.go,build_type.go,build_type_test.go: choose slug builds by default, unless a Dockerfile is present
 - [`45dff0c`](https://github.com/deis/builder/commit/45dff0cb9e374bf15548c135178984df67a56823) glide.yaml: clean up dependency list
 - [`55de9ee`](https://github.com/deis/builder/commit/55de9ee0db74d672b6e6b3f0398654f613d0d094) glide.lock,glide.yaml: remove transitive dependencies of github.com/deis/deis from glide lockfile
 - [`6fe022b`](https://github.com/deis/builder/commit/6fe022b0b6313bdd823f5b7fdf30c7e658002e38) (all): remove dependency on github.com/deis/deis
 - [`439d2e9`](https://github.com/deis/builder/commit/439d2e9033877e380b70ad53eaf0bdd8da26a104) build.go: add informational message for cold builds
 - [`9165b21`](https://github.com/deis/builder/commit/9165b21caf842c6b8c7a725e41be7e4b5cdab344) Dockerfile: merging 2 apk commands
 - [`49c303f`](https://github.com/deis/builder/commit/49c303f24f46dfbda25ec95228620a7408f9cf92) Makefile: set GO15VENDOREXPERIMENT in the build container
 - [`5faceaa`](https://github.com/deis/builder/commit/5faceaa02ec1f0c65689c0c8dec43ba9be696e3e) Makefile,glide.lock: upgrade to glide 0.8 & add lockfile
 - [`4c1843a`](https://github.com/deis/builder/commit/4c1843a111a7621290940ee8f7236cea11586753) Dockerfile,deis-builder-rc.yaml: add DOCKERIMAGE env var

#### Documentation

 - [`e96b33f`](https://github.com/deis/builder/commit/e96b33f42cc3dc874d7df30f625cdca89b9fdc65) README.md: update docs to match beta status

#### Maintenance

 - [`7e45e25`](https://github.com/deis/builder/commit/7e45e25cad219816d045d8553acb171bc781fbb1) Makefile: upgrade the go-dev image to 0.9.1
 - [`4212eb6`](https://github.com/deis/builder/commit/4212eb6a8959185346b192f0cc11de0443ec061a) manifests: remove repository manifests (Proposal
 - [`602cff8`](https://github.com/deis/builder/commit/602cff845aa75fcb0d6857e266df78ede2eb48f3) Makefile: upgrade the go-dev image to 0.8.0
 - [`7b3630e`](https://github.com/deis/builder/commit/7b3630e926fb73f473a891bd0a3b2a49a90fb491) Dockerfile: remove top level dockerfile
 - [`c5601b3`](https://github.com/deis/builder/commit/c5601b398ccc2e080e733eeb5f4a07eaf4d3070b) release: bump version to v2-beta

### 2.0.0-alpha

#### Features

 - [`7858bb7`](https://github.com/deis/builder/commit/7858bb798bb47f5e5dfc78578204d9793b9650b9) builder: add support for external object storage
 - [`caf5524`](https://github.com/deis/builder/commit/caf55242ed952c964b7abf16578495b979c07e8f) (all): add support for uploading tarballs to minio
 - [`e7f1b54`](https://github.com/deis/builder/commit/e7f1b544d017bdb13c2adba998c24b46527ac4cd) deploy.sh: push deisci/builder:v2-alpha images from master

#### Fixes

 - [`20ad31b`](https://github.com/deis/builder/commit/20ad31ba8b058aebcbed3efc03b43d71a7cde9e8) builder: add status messages
 - [`daac4b8`](https://github.com/deis/builder/commit/daac4b822a94554799c8503e5e7662592492b7f0) builder: print buildpack output, decrease verbosity
 - [`572a709`](https://github.com/deis/builder/commit/572a70947d46adb94a019e719291fff1f8c62a66) deis-builder-rc.yaml: fix indentation on deis-builder RC
 - [`696322a`](https://github.com/deis/builder/commit/696322ad799101b09c77e970ce6c20ca8d30a206) builder: ping remote storage to determine when builds are done
 - [`e0547b7`](https://github.com/deis/builder/commit/e0547b7d7deebdfd16e784475051075026c098d9) deis-builder-rc.yaml,builder: create builder pods in correct namespace
 - [`b86f97f`](https://github.com/deis/builder/commit/b86f97fa5e3640f69ce846b2dd02df56ae248e7b) deis-slugbuilder.yaml: use repo_name instead of deis-slugbuilder
 - [`76e6b64`](https://github.com/deis/builder/commit/76e6b6495a0872888536ed93ab447a92b9b1f44d) (all): use alpine linux compatible mc binary
 - [`cb278c1`](https://github.com/deis/builder/commit/cb278c1973c3f988471860940601545f9db6ade1) builder: use DEIS_OUTSIDE_STORAGE_PORT properly
 - [`af2ab12`](https://github.com/deis/builder/commit/af2ab129c608e999b7257a338a0474b0620bc975) (all): fix travis build
 - [`5f192e1`](https://github.com/deis/builder/commit/5f192e12a7f36dfeb4cf8c18bef51e0f0c7af594) builder: use workflow v2 hook urls
 - [`33e16e5`](https://github.com/deis/builder/commit/33e16e54683a20e4608d9a139f014aa4c8b5452e) deis-builder-rc.yaml: add imagePullPolicy: Always to rc manifest
 - [`7afa12e`](https://github.com/deis/builder/commit/7afa12e216239832cde3af33b00571260ccb4f18) Makefile: change VERSION, add and fix targets
 - [`ef436e9`](https://github.com/deis/builder/commit/ef436e93b67f4021cd93981ba98784e367167c03) manifests: mount and use auth secrets correctly and use proper image names
 - [`b183450`](https://github.com/deis/builder/commit/b18345073f1445c1e338924f7ba835fb0cd20bc7) builder: add check to locate Procfile

#### Maintenance

 - [`8ab7b43`](https://github.com/deis/builder/commit/8ab7b43b5020c3d489534ce045114e4e114011e7) release: set version and lock to deis registry
 - [`c0d7342`](https://github.com/deis/builder/commit/c0d734208c8b1da5de5d91d16e72cbf40ba4c99f) Dockerfile: update version
 - [`0951acd`](https://github.com/deis/builder/commit/0951acdd5d275ce2f4a8dbe07af99704f4bfab9b) kubectl: replacing with an alpine-compatible kubectl
 - [`c82f74d`](https://github.com/deis/builder/commit/c82f74d943f760a1f808b7f395c4fbca94a3d097) (all): vendoring all dependencies
