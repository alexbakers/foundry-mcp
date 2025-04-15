# Use official Node.js LTS image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package.json and lock file
COPY package.json bun.lockb ./

# Install dependencies
RUN npm install --production

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Expose port (customize if needed)
EXPOSE 3000

# Start the server
CMD ["npm", "start"]
