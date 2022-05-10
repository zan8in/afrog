# Afrog-PoC Contribution Guidelines

There are two ways to contribute a PoC to afrog-poc.

## Method 1: Submit Issues

#### Step 1: Find Existing PoCs

- Take a look at the [Existing PoC](https://github.com/zan8in/afrog/tree/main/pocs/afrog-pocs) before creating new one.
- Take a look at Existing Templates in [GitHub Issues](https://github.com/zan8in/afrog/issues) and [Pull Request](https://github.com/zan8in/afrog/pulls) section to avoid duplicate work.
- Take a look at [Templates](https://nuclei.projectdiscovery.io/templating-guide/) and [Matchers](https://github.com/projectdiscovery/nuclei-templates/wiki/Unique-Template-Matchers) Guideline for creating new template.
- Check out [PoC Guide](https://github.com/zan8in/afrog/blob/main/pocs/afrog-pocs/README.md)

### Step 2: Write Issues

- Open the browser to submit issues URL: [ISSUES URL](https://github.com/zan8in/afrog/issues)

- Then click the `New Issues` button in the upper right corner
- Fill in `title`, for example: CVE-2022-1234
- Then, fill in the `cve-2020-1234.yaml` code
- Next, select `label` and select `afrog-poc`

- Finally, click the `Submit new issue` button

![con-1](C:\Users\zanbi\go\src\github.com\zan8in\afrog\con-1.png)

## Method 2: Pull Request

#### Step 1: Find Existing PoCs

- Review the [existing PoC library](https://github.com/zan8in/afrog/tree/main/pocs/afrog-pocs) before creating a new PoC
- Review existing PoCs in the [GitHub Issues](https://github.com/zan8in/afrog/issues) and [Pull Requests](https://github.com/zan8in/afrog/pulls) sections to avoid duplication
- Check out [PoC Syntax Guide](https://github.com/zan8in/afrog/blob/main/pocs/afrog-pocs/README.md)

### Step 2: Fork the project

Click the afrog project `fork` button

![](C:\Users\zanbi\go\src\github.com\zan8in\afrog\con-2.png)

```
git clone https://github.com/<your-username>/afrog
cd afrog
git remote add upstream https://github.com/zan8in/afrog
```

- If you've `fork` the project, update your copy before working on it.

```
git remote update
git checkout master
git rebase upstream/master
```

### Step 3: Create your afrog branch

Create a `new branch`

```
git checkout -b afrog_branch_name
```

### Step 4: Write and submit a PoC

- Create and write your PoC
- add to the `branch` you just created

```
git add .
git commit -m "Added CVE-2022-1234.YAML PoC"
```

### Step 5: Push to your remote (forked) repository

```
git push -u origin afrog_branch_name
```

### Step 5: Pull Request

- Browser to open your Github repository
- Click on `Pull Request`
- Then click `New pull request`

![](C:\Users\zanbi\go\src\github.com\zan8in\afrog\con-3.png)

- `compare` select the new `branch` you created (image below)
- Then click `Create pull request` (below)

![con-5](C:\Users\zanbi\go\src\github.com\zan8in\afrog\con-5.png)

- Fill in `title` and `content`, click the `Create pull request` button (below)

![](C:\Users\zanbi\go\src\github.com\zan8in\afrog\con-6.png)

At this point, your `Pull Request` has been submitted, waiting for the moderator to review the merge.

