FROM pandoc/latex:3.10-ubuntu

RUN apt-get update && \
    apt-get install -y --no-install-recommends inkscape nodejs npm && \
    rm -rf /var/lib/apt/lists/*

RUN tlmgr update --self && \
    tlmgr install algorithm2e enumitem mdframed physics siunitx svg xcharter \
    stmaryrd ifoddpage relsize zref needspace transparent lastpage xkeyval \
    xstring fontaxes catchfile stmaryrd siunitx

WORKDIR /app

COPY ./src ./src

EXPOSE 3000

ENTRYPOINT []
CMD ["node", "src/server.js"]
