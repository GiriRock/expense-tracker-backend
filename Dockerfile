# Build stage
FROM rust:1.77-buster As builder

WORKDIR /app

ARG DATABASE_URL

ENV DATABASE_URL=$DATABASE_URL

COPY . .

RUN cargo build --release

#Preduction stage
FROM debian:buster-slim

WORKDIR /user/local/bin

COPY --from=builder /app/target/release/expense-tracker-backend .

CMD [ "./expense-tracker-backend" ]
