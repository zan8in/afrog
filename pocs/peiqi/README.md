---
title: zan8in/afrog
---

<template>
  <div style="background-color: #F5F5F5; padding: 24px;">
    <a-page-header
      :ghost="false"
      title="zan8in/afrog"
      sub-title="一个挖洞工具 - A tool for finding vulnerabilities"
      @back="() => $router.go(-1)"
    >
      <template>
      <a-comment>
        <a slot="author">zan8in</a>
        <a-avatar
          slot="avatar"
          src="/img/afrog.ico"
          alt="afrog"
        />
        <p slot="content">
          afrog 是一个挖洞工具。如果你想挖 SQL 注入、XSS、文件包含等漏洞，AWVS 做得更好，否则试试 afrog。
        </p>
        </a-tooltip>
      </a-comment>
    </template>
      <template slot="extra">
        <a-button href="https://github.com/zan8in/afrog" key="1" type="primary">
          Github
        </a-button>
      </template>
      <a-descriptions size="small" :column="4">
        <a-descriptions-item label="项目创作者">
          <a>zan8in</a>
        </a-descriptions-item>
        <a-descriptions-item label="安全方向">
          <a>漏洞扫描器</a>
        </a-descriptions-item>
        <a-descriptions-item label="创建时间">
          <a>2022-03-28</a>
        </a-descriptions-item>
        <a-descriptions-item label="作者寄语">
          Poc 共[455]个，持续更新，喜欢请点赞🌟⭐，不迷路～
        </a-descriptions-item>
      </a-descriptions>
    </a-page-header>
  </div>
</template>

<style>
tr:last-child td {
  padding-bottom: 0;
}
</style>




<br/>

![image-20220328175728660](img/2.png)

<br/>

![image-20220328175728660](img/3.png)
