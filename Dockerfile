# Use official Node.js LTS image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package.json and lock file
COPY package.json bun.lockb ./

# Install all dependencies (including devDependencies for build)
RUN npm install

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Remove devDependencies for a slim production image
RUN npm prune --production

# Expose port (customize if needed)
EXPOSE 3000

# Start the server
CMD ["npm", "start"]
