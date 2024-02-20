# PhotonIQ VWRS CI/CD

## Integrating CI/CD Pipeline

This directory utilizes CI/CD pipelines to automate waiting room configuration process, specifically configured to trigger on updates of the `photoniq_vwrs.toml` file. Follow the instructions below to integrate this CI/CD pipeline into your Bitbucket or GitHub repository.

### Prerequisites

- A Bitbucket or GitHub account.
- A repository on Bitbucket or GitHub.

### Required Files and Folders

- **`photoniq_vwrs.toml`**: The file defines the waiting room configurations. Place this file in the root of the repository.
- **Bitbucket Workflow File**: `bitbucket-pipelines.yml` Defines the bitbucket pipeline. Place this file in the root of the repository.
- **GitHub Workflow File**: `github-action.yml` Defines the GitHub workflow. Place the `github-action.yml` file in the `.github/workflows` directory.
- **`vwrs_cicd.py`**: Script to read toml file and apply to VWRS.
- **`requirements.txt`**: Requirements needed by vwrs_cicd.py

### Configuration Variables

The `vwrs-cicd.py` script requires the following environment variables:

- **`VWRS_HOST`**: The HOST endpoint for the VWRS service.
- **`VWRS_API_KEY`**: VWRS API key for authenticating against the VWRS service.
- **`TOML_FILE_PATH`**: Path to the `photoniq_vwrs.toml` file within your repository.
  - Default: `photoniq_vwrs.toml`

### Bitbucket Intergration

#### Set Environment Variables in Bitbucket

1. Navigate to your **Repository settings** in Bitbucket.
2. Go to **Repository variables** under Pipelines.
3. Add each of the above variables as a key-value pair.

#### Setup Workflow

Refer to the [Prerequisites](#prerequisites) and [Required Files and Folders](#required-files-and-folders) sections to prepare your repository.

1. **Enable Pipelines**

   - Go to your repository settings on Bitbucket.
   - Locate the Pipelines section and enable Pipelines for your repository.

2. **Add the Pipeline Configuration**

   - Ensure the `bitbucket-pipelines.yml` file is at the root of your repository.

3. **Commit and Push**
   - Commit the required files and push them to your repository.

### GitHub Integration

Refer to the [Prerequisites](#prerequisites) and [Required Files and Folders](#required-files-and-folders) sections to prepare your repository.

#### Set Environment Variables in Gitbub

1. Navigate to your repository **Settings** in GitHub.
2. Click **Secrets**.
3. Add each of the above variables as a new secret.

#### Setup Action

1. **Create GitHub Actions Workflow**

   - Ensure the `.github/workflows/github-action.yml` file is placed correctly.

2. **Commit and Push**
   - Commit the required files and push them to your repository.
