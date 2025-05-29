#!/bin/bash

print_msg() {
    local type=$1
    shift
    local msg=$*

    case "$type" in
        success)
            echo -e "[\033[1;32m+\033[0m] $msg"  # Green +
            ;;
        info)
            echo -e "[\033[1;34m+\033[0m] $msg"  # Blue +
            ;;
        fail)
            echo -e "[\033[1;31m✗\033[0m] $msg"  # Red ✗
            ;;
        warning)
            echo -e "[\033[1;33m!\033[0m] $msg"  # Yellow !
            ;;
        *)
            echo "[?] $msg"
            ;;
    esac
}

if ! git rev-parse --is-inside-work-tree &> /dev/null; then
    print_msg fail "This directory is not inside a Git repository."
    exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
CURRENT_DIR=$(pwd)

if [ "$CURRENT_DIR" != "$REPO_ROOT" ]; then
    print_msg fail "You must run this script from the root of the repository:"
    echo "   cd $REPO_ROOT"
    exit 1
fi

# Check that docker is accessible
print_msg info "Checking if Docker is installed..."
if ! command -v docker &> /dev/null; then
    print_msg fail "Docker is not installed. Please install Docker first."
    exit 1
fi
print_msg success "Docker is installed."

print_msg info "Checking if Docker is accessible..."
if ! docker info &> /dev/null; then
    print_msg fail "Docker is installed but not accessible."
    echo "   Try running with sudo or add your user to the docker group:"
    echo "   sudo usermod -aG docker \$USER"
    echo "   Then log out and back in for changes to take effect."
    exit 1
fi
print_msg success "Docker is accessible."

# Check if the container already exists
if docker ps -a --format '{{.Names}}' | grep -Eq "^firmainc-postgres\$"; then
    print_msg info "Container 'firmainc-postgres' already exists. Restarting it..."
    docker start firmainc-postgres &> /dev/null
    if [ $? -ne 0 ]; then
        print_msg fail "Failed to restart the existing container."
        exit 1
    fi
else
    print_msg info "Creating a new PostgreSQL container..."

    if [ ! -d "$REPO_ROOT/database" ]; then
        print_msg info "Creating database directory at $REPO_ROOT/database"
        mkdir -p "$REPO_ROOT/database"
        if [ $? -ne 0 ]; then
            print_msg fail "Failed to create database directory."
            exit 1
        fi
    fi

    docker run -d \
        --name firmainc-postgres \
        -e POSTGRES_PASSWORD=femu \
        -e POSTGRES_USER=femu \
        -e POSTGRES_DB=firmware \
        -e PGDATA=/var/lib/postgresql/data/pgdata \
        -v $REPO_ROOT/database:/var/lib/postgresql/data \
        -p 4321:4321 \
        postgres &> /dev/null
    if [ $? -ne 0 ]; then
        print_msg fail "Failed to start the PostgreSQL container."
        exit 1
    fi
fi

# Wait for the container to start
while ! docker exec firmainc-postgres pg_isready -U firmadyne &> /dev/null; do
    sleep 1
done

print_msg success "PostgreSQL started successfully."

if docker exec -i firmainc-postgres psql -U firmadyne -d firmware -c "\dt" | grep -q "image"; then
    print_msg info "Database schema already applied. Skipping schema application."
else
    print_msg info "Applying database schema..."
    docker exec -i firmainc-postgres psql -U firmadyne -d firmware < "$REPO_ROOT/database/schema" &> /dev/null
    if [ $? -ne 0 ]; then
        print_msg fail "Could not populate database"
        exit 1
    fi
    print_msg success "Database schema applied successfully."
fi

print_msg success "firmware database populated"

print_msg info "Creating Python enviroment"

# Check if the Python virtual environment already exists
if [ -d "$REPO_ROOT/.venv" ]; then
    print_msg info "Python virtual environment already exists. Skipping creation."
else
    print_msg info "Creating Python virtual environment..."
    python3 -m venv "$REPO_ROOT/.venv"
    if [ $? -ne 0 ]; then
        print_msg fail "Failed to create Python virtual environment."
        exit 1
    fi
    print_msg success "Python virtual environment created successfully."
fi

# Install binwalk
print_msg info "Installing Binwalk..."
source "$REPO_ROOT/.venv/bin/activate"
wget -q https://github.com/George-RG/binwalk/archive/refs/tags/v2.3.5.tar.gz -O binwalk.tar.gz
if [ $? -ne 0 ]; then
    print_msg fail "Failed to download Binwalk."
    exit 1
fi
tar -xzf binwalk.tar.gz
rm binwalk.tar.gz
cd "$REPO_ROOT/binwalk-2.3.5" || exit
./deps.sh --yes &> /dev/null
pip install . &> /dev/null
cd - &> /dev/null
rm -rf "$REPO_ROOT/binwalk-2.3.5"
deactivate

if [ $? -ne 0 ]; then
    print_msg fail "Failed to install Binwalk."
    exit 1
fi

print_msg success "Binwalk installed successfully"

# Activate the virtual environment and install requirements
if [ -f "$REPO_ROOT/requirements.txt" ]; then
    print_msg info "Installing Python dependencies from requirements.txt..."
    source "$REPO_ROOT/.venv/bin/activate"
    pip install -r "$REPO_ROOT/requirements.txt" &> /dev/null
    if [ $? -ne 0 ]; then
        print_msg fail "Failed to install Python dependencies."
        deactivate
        exit 1
    fi
    deactivate
    print_msg success "Python dependencies installed successfully."
else
    print_msg warning "No requirements.txt found. Skipping dependency installation."
fi

if [ -d "$REPO_ROOT/analyses/routersploit" ]; then
    if [ "$(ls -A "$REPO_ROOT/analyses/routersploit")" ]; then
        source "$REPO_ROOT/.venv/bin/activate"
        pip install -r "$REPO_ROOT/analyses/routersploit/requirements.txt" &> /dev/null
        deactivate
        cd "$REPO_ROOT/analyses/routersploit" && patch -p1 < ../routersploit_patch && cd "$REPO_ROOT" &> /dev/null
        print_msg info "Routersploit configured successfully."
    else
        print_msg warning "Routersploit was not found. Skipping (this may affect analyses)."
    fi
else
    print_msg warning "Routersploit was not found. Skipping (this may affect analyses)."
fi

