import express from 'express';

import { Sequelize, DataTypes ,Op} from "sequelize";
import { v4 as uuidv4 } from "uuid";
import axios from 'axios';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import fs_extra from 'fs-extra';
import yaml from 'js-yaml';
import path from 'path';
import crypto from 'crypto';
import si from 'systeminformation';
import { WebSocketServer } from 'ws';
import { StatusCode } from './common.js';

// 日志模块
import { createLogger } from './logger.js';
const logger = await createLogger('luyaocode.github.io.server');

// 创建 Sequelize 实例，使用 SQLite 连接数据库
const initdb = () => {
    const sequelize = new Sequelize({
        dialect: 'sqlite',
        storage: 'luyaocode.github.io.db' // 数据库文件路径
    });

    // 定义标签模型
    const Tag = sequelize.define('Tag', {
        id: {
            type: DataTypes.INTEGER,
            autoIncrement: true,
            primaryKey: true,
        },
        name: {
            type: DataTypes.STRING,
            unique: false,
            allowNull: false
        }
        },
        {
            tableName: 'tag',
            timestamps: true, // 启用时间戳
            paranoid: true, // 启用软删除
        }
    );

    // 定义文章模型
    const Blog = sequelize.define('Blog',
        {
            id: {
                type: DataTypes.UUID,
                defaultValue: uuidv4,
                primaryKey: true,
            },
            title: {
                type: DataTypes.STRING,
                allowNull: false
            },
            author: {
                type: DataTypes.STRING,
                allowNull:false
            },
            content: {
                type: DataTypes.TEXT,
                allowNull: false
            },
            time: {
                type: DataTypes.DATE,
                defaultValue:new Date(),
                allowNull: false
            },
        },
        {
            tableName: 'blog',
            timestamps: true, // 启用时间戳
            paranoid: true, // 启用软删除
        }
    );
    // 钩子：在销毁之前更新 `updatedAt` 字段
    Blog.beforeDestroy(async (instance, options) => {
        await instance.update({ updatedAt: new Date() }, { silent: true });
    });

    // 定义多对多关联
    const BlogTag = sequelize.define('BlogTag', {
        tableName: 'blog_tag', // 可选: 指定表名
        timestamps: true, // 启用时间戳
        paranoid: true, // 启用软删除
    });

    // 设置模型关联
    Blog.belongsToMany(Tag, { through: BlogTag });
    Tag.belongsToMany(Blog, { through: BlogTag });

    // 创建User模型
    const User = sequelize.define('User', {
        id: {
            type: DataTypes.INTEGER,  // 自增主键
            primaryKey: true,         // 设置为主键
            autoIncrement: true,      // 自增
        },
        githubUserId: {
            type: DataTypes.STRING,
            allowNull: false,
            unique: true,             // 确保 githubUserId 唯一
        },
        role: {
            type: DataTypes.ENUM('admin', 'user'), // 角色字段
            allowNull: false,
            defaultValue: 'user',  // 默认角色为 user
        },
    }, {
        timestamps: true,  // 自动管理 createdAt 和 updatedAt
    });

    // 同步数据库
    // sequelize.sync({ force: true }); // 清空数据库，慎用
    sequelize.sync()
    .then(() => {
        logger.info('数据库已同步');
    })
    .catch(err => {
        logger.error('同步失败:', err);
    });

    return { sequelize, Blog, Tag, BlogTag, User };
}

// 检查是否启用了软删除
const isParanoidEnabled = (model) => {
    return model.options.paranoid === true;
};


// 中间件
const AUTH_ENABLED = true; // 是否鉴权，测试关闭，上线开启

const verifyTokenPromise = (token) => {
    return new Promise((resolve, reject) => {
      const client = new authProto.AuthService(`localhost:${GRPC_PORT}`, grpc.credentials.createInsecure());
      client.VerifyToken({ token }, (err, response) => {
        if (err || !response.valid) {
          reject('Token is invalid');
        } else {
          resolve(response);  // 返回验证结果
        }
      });
    });
};

// 鉴权中间件
const authMiddleware = async (req, res, next) => {
    const token = req.cookies[AUTH_TOKEN];

    if (!token) {
      return res.status(StatusCode.Unauthorized).send("无效token");
    }

    try {
        const response = await verifyTokenPromise(token);
        const { userId } = response;
        if (parseInt(userId) !== myGithubId) {
            logger.info("用户 "+userId +"未授权");
            return res.status(StatusCode.Unauthorized).send("用户 "+userId +"未授权");
        }
        next();
    } catch (error) {
      logger.error('Token verification failed:', error);
      return res.status(StatusCode.Unauthorized).send("未授权");
    }
};

// 鉴权中间件
const logoutMiddleware = async (req, res, next) => {
    const token = req.cookies[AUTH_TOKEN];

    if (!token) {
      return res.status(StatusCode.Unauthorized).send("无效token");
    }

    try {
        const response = await verifyTokenPromise(token);
        const { userId } = response;
        if (parseInt(userId)<0) {
            logger.info("用户 "+userId +"未授权");
            return res.status(StatusCode.Unauthorized).send("用户 "+userId +"未授权");
        }
        next();
    } catch (error) {
      logger.error('Token verification failed:', error);
      return res.status(StatusCode.Unauthorized).send("未授权");
    }
};

/**
 * 测试用
 */
const test = async () => {
    async function printBlogsWithTags() {
        const { Blog, Tag } = db; // 确保 db 中导入了 Blog 和 Tag 模型

        try {
            // 查询所有博客，并包括关联的标签
            const blogs = await Blog.findAll({
                include: [{
                    model: Tag,
                    through: { attributes: [] } // 只选择关联表的内容，忽略中间表的属性
                }]
            });

            // 打印每个博客及其关联的标签
            blogs.forEach(blog => {
                logger.info(`博客 ID: ${blog.id}, 标题: ${blog.title}, 作者: ${blog.author}, 时间: ${blog.time}`);
                logger.info('关联的标签:');
                blog.Tags.forEach(tag => {
                    logger.info(`- ${tag.name}`);
                });
            });
        } catch (error) {
            logger.error('查询失败:', error);
        }
    }

    // 执行函数
    printBlogsWithTags();
}

const db = initdb(); // 单例

// 标签操作
// 创建单个标签
async function createTag(name, transaction = null) {
    if (name === ''||name==undefined) {
        return;
    }
    const { Tag } = db;
    try {
        let tag = await Tag.findOne({ where: { name } },transaction);
        if (tag) {
            logger.info(`标签已存在: ${tag.name}`);
            return;
        }
        tag = await Tag.create({ name }, {transaction});
        logger.info(`标签已创建: ${tag.name}`);
        return true;
    } catch (error) {
        logger.error('创建标签失败:', error);
        throw error;
    }
}

// 创建多个标签
async function createTags(tags,transaction) {
    if (tags) {
        for (const tag of tags) {
            await createTag(tag,transaction);
        }
    }
}

// 查询所有标签
async function getAllTags() {
    const { Tag } = db;
    try {
        const tags = await Tag.findAll({
            attributes: ['id', 'name'] // 仅查询 id 和 name 字段
        });
        logger.info('所有标签:', tags);
        return tags;
    } catch (error) {
        logger.info('查询标签失败:', error);
        return [];
    }
}

// 查询某博客的所有标签
const getTagsByBlogId = async (blogId) => {
    const { Blog,Tag } = db;
    try {
        const blog = await Blog.findOne({
            where: { id: blogId },
            include: {
                model: Tag,
                attributes: ['id', 'name'],
                through: { attributes: [] }
            }
        });
        return blog ? blog.Tags.map(tag => tag.get({ plain: true })) : [];
    } catch (error) {
        logger.error('获取标签时出错:', error);
        throw error;
    }
};

// 查询所有标签，按照文章数量排序
async function getAllTagsWithPostCounts(withBlogs=true) {
    const { Blog, Tag } = db;
    try {
        // 获取标签及其博客数量
        const tagsWithCounts = await Tag.findAll({
            attributes: [
                "id",
                "name",
                [db.sequelize.fn("COUNT", db.sequelize.col("Blogs.id")), "blogCount"]
            ],
            include: [
                {
                    model: Blog,
                    attributes: ["id", "title", "author", "time"], // 选择所需的博客字段
                    through: { attributes: [] } // 排除中间表字段
                }
            ],
            group: ["Tag.id"], // 按 Tag.id 分组
            order: [[db.sequelize.fn("COUNT", db.sequelize.col("Blogs.id")), "DESC"]], // 按博客数量降序排列
            nest: true, // 使返回数据更具可读性
        });

        if (!withBlogs) {
            const result = tagsWithCounts.map((tag) => {
                return {
                    id: tag.id,
                    name: tag.name,
                    blogCount: tag.dataValues.blogCount,
                }
            });
            return result;
        }
        // 获取每个标签的所有相关博客，并只返回数据
        const tagsWithBlogs = await Promise.all(tagsWithCounts.map(async (tag) => {
            const blogs = await tag.getBlogs(); // 获取关联的博客
            const blogData = blogs.map(blog => ({
                id: blog.id,
                title: blog.title,
                author: blog.author,
                time: blog.time
            })); // 提取每个博客的必要属性
            return {
                id: tag.id,
                name: tag.name,
                blogCount: tag.dataValues.blogCount,
                Blogs: blogData
            };
        }));

        return tagsWithBlogs;
    } catch (error) {
        logger.error("Error fetching tags with blogs sorted by blog count:", error);
        throw error;
    }
}

// 查询所有博客，按照文章创建时间降序排序
async function getAllBlogsWithTags() {
    try {
        const { Blog, Tag } = db;
        const blogsWithTags = await Blog.findAll({
            attributes: ["id", "title", "time"],
            order: [['createdAt', 'DESC']], // 按照时间字段倒序排序
            include: [
                {
                    model: Tag,
                    attributes: ["id", "name"],
                    through: { attributes: [] }, // 排除中间表 BlogTag 的所有字段
                },
            ],
            // where: {
            //     // 添加条件，确保查询到的博客有关联标签
            //     '$Tags.id$': {
            //         [Sequelize.Op.ne]: null // 只返回关联 id 不为 null 的博客
            //     }
            // },
            raw: false,
            nest: true,
        });
        // 确保 Tags 始终是数组
        const result = blogsWithTags.map(blog => {
            // 将 Tags 转换为数组，确保即使只有一个标签也能处理
            blog.Tags = blog.Tags || []; // 确保 Tags 不为 null
            return {
                id: blog.id,
                title: blog.title,
                time: blog.time,
                Tags: blog.Tags.map(tag => ({
                    id: tag.id,
                    name: tag.name,
                })),
            };
        });
        return result;
    } catch (error) {
        logger.error(error);
        return [];
    }
}


// 根据多个标签名查询对应id数组
async function getTagIdsByNames(tagNames,transaction=null) {
    const { Tag } = db;
    try {
        const tags = await Tag.findAll({
            where: {
                name: tagNames
            },
            attributes: ['id']
        },transaction);

        const tagIds = tags.map(tag => tag.id);
        return tagIds;
    } catch (error) {
        logger.error('Error fetching tag IDs:', error);
        throw error;
    }
}

// 更新标签
async function updateTag(tagId, newName) {
    const { sequelize, Tag } = db;
    const transaction = await sequelize.transaction();
    try {
        const tag = await Tag.findByPk(tagId, { transaction }); // 在事务中查找标签
        if (!tag) {
            logger.info(`未找到标签 ID: ${tagId}`);
            return false;
        }

        const existingTag = await Tag.findOne({ where: { name: newName }, transaction });
        if (existingTag) {
            logger.info(`标签名称已存在: ${newName}`);
            return false;
        }

        tag.name = newName;
        await tag.save({ transaction });
        await transaction.commit();
        logger.info(`标签已更新: ${tagId} -> ${newName}`);
        return true;
    } catch (error) {
        await transaction.rollback();
        throw error;
    }
}

// 删除标签
async function deleteTagById(tagId) {
    const { Tag } = db;
    try {
        const deletedCount = await Tag.destroy({
            where: { id: tagId }
        });
        if (deletedCount > 0) {
            logger.info(`已删除标签 ID: ${tagId}`);
            return true;
        } else {
            logger.info(`未找到标签 ID: ${tagId}`);
            return false;
        }
    } catch (error) {
        throw error;
    }
}

// 博客操作
const postBlog = async (uuid, title, content,tags) => {
    const { sequelize, Blog } = db;
    const transaction = await sequelize.transaction(); // 创建外层事务
    try {
        // 创建一个嵌套事务
        const nestedTransaction = await sequelize.transaction();
        let newPost;
        try {
            newPost = await Blog.create({
                id: uuid,
                title: title,
                author: 'luyaocode',
                content: content,
                time: new Date()
            }, { nestedTransaction });
            await createTags(tags, nestedTransaction);
            await nestedTransaction.commit();
        }catch (nestedError) {
            await nestedTransaction.rollback(); // 回滚嵌套事务
            logger.error('嵌套事务发生错误:', nestedError);
        }
        // 关联
        if (newPost) {
            const tagIds=await getTagIdsByNames(tags,transaction);
            newPost.setTags(tagIds);
        }
        logger.info(`New post created: ${uuid}`);
    } catch (error) {
        await transaction.rollback();
        logger.error('Error occurred:', error);
    }
}


// 更新博客
const updateBlog = async (uuid, title, content) => {
    const { Blog } = db;
    try {
        const [updatedRows] = await Blog.update(
            {
                title: title,
                content: content,
                time: new Date() // 更新记录的时间
            },
            {
                where: { id: uuid }
            }
        );

        if (updatedRows > 0) {
            logger.info(`Blog post with ID ${uuid} was successfully updated.`);
            return true;
        } else {
            logger.warn(`No blog post found with ID ${uuid}.`);
            return false;
        }
    } catch (error) {
        logger.error('Error occurred while updating blog:', error);
        return false;
    }
}

// 更新时创建博客
const writeThroughBlog = async (uuid, title, content,tags) => {
    const { Blog } = db;
    try {
        // 尝试更新记录
        const [updatedRows] = await Blog.update(
            {
                title: title,
                content: content,
                time: new Date() // 更新记录的时间
            },
            {
                where: { id: uuid }
            }
        );

        // 如果更新操作没有影响任何行，说明记录不存在
        if (updatedRows > 0) {
            logger.info(`Blog post with ID ${uuid} was successfully updated.`);
            return uuid;
        } else {
            logger.warn(`No blog post found with ID ${uuid}. Creating new record...`);

            try {
                postBlog(uuid,title,content,tags);
                // 如果记录不存在，创建新的记录
                // const newBlog = await Blog.create({
                //     id: uuid,       // 使用提供的 uuid
                //     title: title,   // 设置标题
                //     author: 'luyaocode', // 作者
                //     content: content, // 设置内容
                //     time: new Date() // 创建时间
                // });

                // logger.info(`New blog post with ID ${uuid} was successfully created.`);
                return uuid;
            } catch (error) {
                // 如果创建操作失败，记录异常
                logger.error(`Error occurred while creating blog post with ID ${uuid}:`, error);
                return false;
            }
        }
    } catch (error) {
        logger.error('Error occurred while updating or creating blog:', error);
        return false;
    }
}

// 更新博客标题
const updateBlogTitle = async (uuid, title) => {
    const { Blog } = db;
    try {
        const [updatedRows] = await Blog.update(
            {
                title: title // 仅更新标题
            },
            {
                where: { id: uuid }
            }
        );

        if (updatedRows > 0) {
            logger.info(`Blog post with ID ${uuid} was successfully updated.`);
            return true;
        } else {
            logger.warn(`No blog post found with ID ${uuid}.`);
            return false;
        }
    } catch (error) {
        logger.error('Error occurred while updating blog title:', error);
        return false;
    }
}

// 查询所有博客，不带任何条件，按照时间降序
const getBlogs = async () => {
    const {Blog}=db;
    try {
        const blogs = await Blog.findAll({
            attributes: ['id', 'title', 'author', 'time'], // 选择需要的字段
            order: [['time', 'DESC']] // 按照时间字段倒序排序
        });
        const res = blogs.map(blog => {
            logger.info(`Title: ${blog.title}, Author: ${blog.author}, Time: ${blog.time}`);
            return {
                id: blog.id,
                title: blog.title,
                author: blog.author,
                time: blog.time,
            }
        });
        return res;
    } catch (error) {
        logger.error('Error occurred:', error);
    }
}

// 查询博客，根据标签数组，返回结果带Tags属性
const getBlogsByTags = async (tags) => {
    if (!tags || tags.length === 0) {
        return await getAllBlogsWithTags(); // 如果没有标签，获取所有博客
    }

    const { Blog, Tag } = db;
    try {
        const blogs = await Blog.findAll({
            attributes: ['id', 'title', 'author', 'time'], // 选择需要的字段
            include: [{
                model: Tag,
                where: {
                    id: {
                        [Op.in]: tags // 使用 Op.in 查询符合条件的标签
                    }
                },
                through: { attributes: [] } // 不返回中间表的字段
            }],
            group: ['Blog.id'], // 按博客 ID 分组
            having: Sequelize.literal(`COUNT("Tags"."id") = ${tags.length}`), // 确保所有标签都匹配
            order: [['time', 'DESC']], // 按时间倒序排序
            logging: console.log // 记录 SQL 查询到控制台
        });

        // 获取每个博客的标签
        const blogsWithTags = await Promise.all(blogs.map(async (blog) => {
            const tags = await blog.getTags(); // 获取标签
            logger.info(`Title: ${blog.title}, Author: ${blog.author}, Time: ${blog.time}`);
            return {
                id: blog.id,
                title: blog.title,
                author: blog.author,
                time: blog.time,
                Tags: tags
            };
        }));

        return blogsWithTags;
    } catch (error) {
        logger.error('查询错误:', error);
        return [];
    }
};

// 查询博客，根据id
const getBlogById = async (id) => {
    const { Blog } = db;
    try {
        // 查找指定 id 的记录
        const blog = await Blog.findOne({
            where: { id: id },
            attributes: ['id', 'title', 'author', 'content', 'time'] // 选择需要的字段
        });

        // 如果找到记录，返回所需字段的对象
        if (blog) {
            const result = {
                id: blog.id,
                title: blog.title,
                author: blog.author,
                content: blog.content,
                time: blog.time,
            };

            logger.info(`Found blog - Title: ${result.title}, Author: ${result.author}, Content: ${result.content.substring(0,20)},,Time: ${result.time}`);
            return result;
        } else {
            logger.info(`No blog found with id: ${id}`);
            return null;
        }
    } catch (error) {
        logger.error('Error finding blog by id:', error);
        return null;
    }
};

// 查询博客，根据id数组
const getBlogsByIds = async (ids) => {
    const { Blog } = db;
    try {
        const blogs = await Blog.findAll({
            attributes: ['id', 'title', 'author', 'time'], // 选择需要的字段
            order: [['time', 'DESC']], // 按照时间字段倒序排序
            ...(ids.length > 0 // 如果 blogIds 不为空，则根据其进行过滤
                ? {
                    where: {
                        id: ids
                    }
                }
                : {})
        });
        const res = blogs.map(blog => {
            logger.info(`Title: ${blog.title}, Author: ${blog.author}, Time: ${blog.time}`);
            return {
                id: blog.id,
                title: blog.title,
                author: blog.author,
                time: blog.time,
            }
        });
        return res;
    } catch (error) {
        logger.error('Error finding blog by id:', error);
    }
}

// 修改博客标签
async function updateBlogTags(blogId,tagIds) {
    const { Blog, Tag, sequelize } = db;
    const transaction = await sequelize.transaction();
    try {
        // 查找博客
        const blog = await Blog.findByPk(blogId, { transaction });
        if (!blog) {
            logger.error(`Blog with ID ${blogId} not found.`);
            throw new Error(`Blog not found`);
        }

        // 查找标签
        const validTags = await Tag.findAll({
            where: { id: tagIds },
            attributes: ['id'],
            transaction,
        });

        // 清空现有标签
        await blog.setTags([], { transaction });

        // 如果没有有效的标签 ID，直接提交事务
        if (validTags.length === 0) {
            await transaction.commit();
            return;
        }

        // 如果找到有效的标签，则关联这些标签
        if (validTags.length > 0) {
            await blog.setTags(validTags, { transaction });
        }
        // 提交事务
        await transaction.commit();
    } catch (error) {
        // 回滚事务
        await transaction.rollback();
        logger.error('Error updating blog tags:', error);
        throw error;
    }
}

// 删除指定 ID 的记录
async function deleteBlogById(id) {
    const { Blog } = db;
    try {
        const deletedRows = await Blog.destroy({
            where: {
            id: id
            }
        });
        logger.info(`Deleted ${deletedRows} rows`);
    } catch (error) {
        logger.error('Error deleting blog:', error);
    }
}

const getTableLatestUpdate = async (model) => {
    try {
        // 获取最新的更新时间记录
        const latestUpdate = await model.findOne({
            order: [['updatedAt', 'DESC']],
            paranoid: false,
        });

        // 获取最新的创建时间记录
        const latestCreated = await model.findOne({
            order: [['createdAt', 'DESC']],
            paranoid: false,
        });


        let latestDeleted;
        // 获取最新的删除时间记录(软删除才有)
        if (isParanoidEnabled(model)) {
            latestDeleted = await model.findOne({
                order: [['deletedAt', 'DESC']],
                paranoid: false,
            });
        }

        // 比较两个记录的时间戳并返回最新的记录
        let latestTimestamp=-999;
        let latestUpdateTime = -999;
        let latestCreateTime = -999;
        let latestDeleteTime = -999;
        if(latestUpdate) latestUpdateTime = new Date(latestUpdate.updatedAt).getTime();
        if(latestCreated) latestCreateTime = new Date(latestCreated.createdAt).getTime();
        if(latestDeleted) latestDeleteTime = new Date(latestDeleted.deletedAt).getTime();
        const timestamps = [latestUpdateTime, latestCreateTime, latestDeleteTime].filter(ts => ts !== null);
        latestTimestamp = timestamps.length > 0 ? Math.max(...timestamps) : latestTimestamp;
        return latestTimestamp;
    } catch (error) {
        logger.error('Error fetching the latest record:', error);
        return null;
    }
}

/**
 *
 * @returns 最新的修改记录（包括软删除、增加、修改）
 */
const getDataLatestUpdate = async (timepoint) => {
    const { Blog,Tag ,BlogTag} = db;
    try {
        const blogsTimestamp = await getTableLatestUpdate(Blog);
        const tagsTimestamp = await getTableLatestUpdate(Tag);
        const blogTagTimestamp = await getTableLatestUpdate(BlogTag);
        // 将所有时间戳放入数组，过滤掉 null 值
        const timestamps = [blogsTimestamp, tagsTimestamp, blogTagTimestamp].filter(ts => ts !== null);
        // 取最大值
        const latestTimestamp = timestamps.length > 0 ? Math.max(...timestamps) : Date.now();

        if (latestTimestamp > timepoint) { // 返回最新数据
            const blogs = await getAllBlogsWithTags();
            const tags = await getAllTagsWithPostCounts(false);
            return {
                timestamp: latestTimestamp,
                blogs: blogs,
                tags:tags
            }
        }
        else { // 返回空数据,不更新了
            return null;
        }
    } catch (error) {
        logger.error('Error fetching the latest record:', error);
        return null;
    }
};

/**
 * 恢复所有软删除的记录
 * @returns None
 */
async function restoreAllBlogs() {
    const { Blog } = db;
    try {
        const restoredRows = await Blog.restore({
            where: {}, // 不指定条件，恢复所有软删除记录
            // paranoid: true // 确保这是一个软删除的恢复
        });

        if (restoredRows > 0) {
            logger.info(`Restored ${restoredRows} blogs`);
        } else {
            logger.info('No soft-deleted blogs found to restore');
        }
    } catch (error) {
        logger.error('Error restoring blogs:', error);
    }
}
// restoreAllBlogs();

import http from 'http';
import https from 'https';
import fs from 'fs';

const app = express();
const port = 5001;

let ssl_crt, ssl_key;
let server, options;
if (process.env.NODE_ENV === 'prod') {
    ssl_crt = path.join(process.cwd(), './ssl/s.pem');
    ssl_key = path.join(process.cwd(), './ssl/s.key');
    options = {
        key: fs.readFileSync(ssl_key),
        cert: fs.readFileSync(ssl_crt)
    }
    server = https.createServer(options, app);
}
else if (process.env.NODE_ENV === 'dev') {
    server = http.createServer(app);
}

// 同步加载和解析 YAML 文件
let paras = {};
try {
    const fileContents = fs.readFileSync('config.yaml', 'utf8');  // 同步读取文件
    const data = yaml.load(fileContents);
    paras["domain"] = data.domain;
} catch (error) {
    console.error('Error reading or parsing the YAML file:', error);
}

// 设置请求体大小限制为 50MB（默认是 1MB）
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ limit: '20mb', extended: false }));

// 使用解析cookie的中间件
app.use(cookieParser());

// 设置跨域
const allowedOrigins = ['https://blog.chaosgomoku.fun']; // 前端域名白名单

// 允许来自任何域名的连接
app.use((req, res, next) => {
    const origin = req.headers.origin;
    // if (!origin) return;
    // if (allowedOrigins.includes(origin)) {
    if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    // }

     // 设置允许的 HTTP 方法
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    // 对于预检请求（OPTIONS 请求），直接返回 200
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

// 校验暗号
const check = (pwd) => {
    if (!Array.isArray(pwd) || pwd.length !== 7) {
        return false;
    }

    const today = new Date();
    let dayOfWeek = today.getDay();
    if (dayOfWeek === 0) {
        dayOfWeek = 7;
    }
    // 检查数组中的条件
    for (let i = 0; i < pwd.length; i++) {
        if (i === dayOfWeek - 1) {
            if (Number(pwd[i]) !== dayOfWeek) {
                return false;
            }
        } else {
            if (pwd[i] !== '') {
                return false;
            }
        }
    }
    return true;
}


// 测试
if (process.env.NODE_ENV === 'dev') {
    app.get("/test", (req, res) => {
        res.status(200).send({ status:'ok',message:"Server is running"});
    })
}

// 处理 POST 请求的路由
app.post('/publish', AUTH_ENABLED ? authMiddleware : (req, res, next) => next(), async (req, res) => {
    const { type, uuid, title, content } = req.body;
    const pwd = req.body['pwd[]']; // 参数为数组
    // 若 tags[] 参数只有一个值，req.body['tags[]'] 会被解析为一个字符串，而不是数组。
    // 这是由 Express 的 body - parser 或其他中间件的默认行为决定的。
    // 当参数只有一个值时，它默认作为单个字符串处理；当有多个值时，才会作为数组处理。
    // 这里强制使用数组
    const tags = Array.isArray(req.body['tags[]']) ? req.body['tags[]'] : [req.body['tags[]']];

    try {
        if (!check(pwd)) {
            res.status(200).send({data: "博客上传失败！暗号错误",code:-1});
            return;
        }
        if (type === 'blog') {
            postBlog(uuid,title,content,tags);
        }
        // 向父进程发送消息
        // process.send({ received: true });
        // 发送状态码为 200 和消息给客户端，并设置 CORS 头部，通配符允许所有来源的ip地址的访问
        res.status(200).send({ data:"博客上传成功！",code:0});
    }
    catch(error) {
        logger.error(error);
    }
});

// 处理 POST 请求的路由
app.post('/update', AUTH_ENABLED ? authMiddleware : (req, res, next) => next(), async (req, res) => {
    const { type, uuid, title, content } = req.body;
    const pwd = req.body['pwd[]'];
    let opRet = false;
    try {
        if (!check(pwd)) {
            res.status(200).send({data: "博客上传失败！暗号错误",code:-1});
            return;
        }
        if (type === 'blog') {
            opRet= await updateBlog(uuid,title,content);
        }
        // 向父进程发送消息
        // process.send({ received: true });
        // 发送状态码为 200 和消息给客户端，并设置 CORS 头部，通配符允许所有来源的ip地址的访问
        if (opRet) {
            res.status(200).send({ data:"博客修改成功！",code:0});
        }
        else {
            res.status(200).send({data: "博客修改失败",code:-2});
        }
    }
    catch(error) {
        logger.error(error);
    }
});

// 写时创建，如果没有记录就创建
app.post('/write-through', AUTH_ENABLED ? authMiddleware : (req, res, next) => next(), async (req, res) => {
    const { type, uuid, title, content } = req.body;
    // const pwd = req.body['pwd[]'];
    const tags = Array.isArray(req.body['tags[]']) ? req.body['tags[]'] : [req.body['tags[]']];

    let opRet = false;
    try {
        // if (!check(pwd)) {
        //     res.status(200).send({data: "博客上传失败！暗号错误",code:-1});
        //     return;
        // }
        if (type === 'note') {
            opRet= await writeThroughBlog(uuid,title,content,tags);
        }
        if (opRet) {
            res.status(200).send({
                data: "笔记创建成功",
                code: 0,
                id: opRet
            });
        }
        else {
            res.status(200).send({data: "笔记创建失败",code:-2});
        }
    }
    catch(error) {
        logger.error(error);
    }
});

// 修改博客标题
app.put('/blogs/:blogId/title', AUTH_ENABLED ? authMiddleware : (req, res, next) => next(), async (req, res) => {
    const { blogId } = req.params;
    const { title } = req.body;
    try {
        await updateBlogTitle(blogId,title);
        const result = await getAllBlogsWithTags();
        res.status(200).send(result);
    }
    catch(error) {
        logger.error(error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// 查询blogs最近更新时间
app.get('/blogs/get-latest-update-time', async (req, res) => {
    const { latestUpdateTime } = req.query;
    let timepoint=0;
    if (latestUpdateTime) {
        timepoint = Number(latestUpdateTime);
        if (isNaN(timepoint)) timepoint = 0;
    }
    try {
        const result = await getDataLatestUpdate(timepoint);
        res.status(200).send(result);
    } catch (error) {
        logger.error(error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});


// 根据标签ids查询博客
app.get('/blogs', async (req, res) => {

    const tags = req.query.tags;
    try {
        const blogs=await getBlogsByTags(tags);
        res.status(200).send(blogs);
    }
    catch(error) {
        logger.error(error);
    }
});

app.get("/blogs_tags", async (req, res) => {
    try {
        const result = await getAllBlogsWithTags();
        res.status(200).send(result);
    } catch (error) {
        logger.error(error);
        res.status(500).send({ error: "服务器错误" });
    }
});

app.get("/tags_blogs", async (req, res) => {
    // test();
    try {
        const result = await getAllTagsWithPostCounts();
        res.status(200).send(result);
    } catch (error) {
        logger.error(error);
        res.status(500).send({ error: "服务器错误" });
    }
});

// 查询博客：按照id
app.get('/blog', async (req, res) => {

    try {
        const { id } = req.query;
        const blog=await getBlogById(id);
        res.status(200).send(blog);
    }
    catch(error) {
        logger.error(error);
        res.status(500).send({ error: "服务器错误" });
    }
});


// 删除博客：在博客浏览界面
app.post('/delblog', AUTH_ENABLED ? authMiddleware : (req, res, next) => next(),async (req, res) => {
    const pwd = req.body['pwd[]'];
    try {
        if (!check(pwd)) {
            res.status(200).send({data: "博客删除失败！暗号错误",code:-1});
            return;
        }
        const { id } = req.body;
        await deleteBlogById(id);
        res.status(200).send({data: "博客删除成功",code:0});
    }
    catch(error) {
        logger.error(error);
    }
});

// 删除博客：在管理界面
app.delete('/blogs/:id', AUTH_ENABLED ? authMiddleware : (req, res, next) => next(),async (req, res) => {
    const blogId = req.params.id;
    try {
        await deleteBlogById(blogId);
        const result=await getAllBlogsWithTags();
        res.status(200).send(result);
    } catch (error) {
        logger.error('删除博客失败:', error);
        res.status(500).send("删除博客失败");
    }
});

// 标签
// 查询tags
app.get('/tags', async (req, res) => {

    try {
        const tags=await getAllTags();
        res.status(200).send(tags);
    }
    catch(error) {
        logger.error(error);
    }
});

// 获取特定博客的标签
app.get('/blogs/:blogId/tags', async (req, res) => {
    const { blogId } = req.params;
    try {
        const tags = await getTagsByBlogId(blogId);
        res.status(200).send(tags);
    } catch (error) {
        logger.error(error);
        res.status(500).send({ error: '服务器错误' });
    }
});

// 修改特定博客的标签
app.put('/blogs/:blogId/tags', AUTH_ENABLED ? authMiddleware : (req, res, next) => next(),async (req, res) => {
    const { blogId } = req.params;
    let tagIds = req.body['tagIds[]'];
    if (!tagIds) {
        tagIds = [];
    }
    else if (!Array.isArray(tagIds)) {
        tagIds = [tagIds];
    }
    try {
        await updateBlogTags(blogId, tagIds);
        const result = await getAllBlogsWithTags();
        res.status(200).send(result);
    } catch (error) {
        logger.error(error);
        res.status(500).send({ error: '服务器错误' });
    }
});

// 修改tag
app.put('/tags/:id', AUTH_ENABLED ? authMiddleware : (req, res, next) => next(),async (req, res) => {
    const tagId = parseInt(req.params.id);
    const { name } = req.body;
    try {
        await updateTag(tagId, name);
        const result=await getAllTagsWithPostCounts();
        res.status(200).send(result);
    } catch (error) {
        logger.error(error);
    }
});

// 删除标签
app.delete('/tags/:id', AUTH_ENABLED ? authMiddleware : (req, res, next) => next(),async (req, res) => {
    const tagId = req.params.id;
    try {
        await deleteTagById(tagId);
        const result=await getAllTagsWithPostCounts();
        res.status(200).send(result);
    } catch (error) {
        logger.error('删除标签失败:', error);
        res.status(500).send("删除标签失败");
    }
});

// 新增标签
app.post('/tags', AUTH_ENABLED ? authMiddleware : (req, res, next) => next(),async (req, res) => {
    const { name } = req.body;
    try {
        await createTag(name);
        const result=await getAllTagsWithPostCounts();
        res.status(200).send(result);
    } catch (error) {
        logger.error('新增标签失败:', error);
        res.status(500).send("新增标签失败");
    }
});

// 三方授权
const access_token_params = {
    client_id: "Iv23liOH77T5kmvXYkx8",
    client_secret: "2049b265b21c4a25664400d42732cceda6f7c82c",
}
const myGithubId = 59311239;// 授权用户白名单
const SECRET_KEY = 'luyaocode.github.io'; // 用于签名 JWT 的密钥
const AUTH_TOKEN = 'auth_token';

// 验证 Token 的函数
const isTokenValid = async (token) => {
    try {
        const decoded = await new Promise((resolve, reject) => {
            jwt.verify(token, SECRET_KEY, (err, decoded) => {
                if (err) {
                    logger.error("token验证失败: token:" + token + " error:" + err);
                    return reject(err);
                }
                resolve(decoded); // 如果验证通过，返回解码后的内容
            });
        });

        // 返回解码后的 userId 和验证通过的状态
        return { valid: true, userId: decoded.userId };
    } catch (err) {
        logger.error("验证失败: " + err);
        return {
            valid: false,
            userId: null
        };
    }
};


app.get("/blogs_man", AUTH_ENABLED ? authMiddleware : (req, res, next) => next(), async (req, res) => {
    try {
        const result = await getAllTagsWithPostCounts();
        res.status(200).send(result);
    } catch (error) {
        logger.error(error);
        res.status(500).send({ error: "服务器错误" });
    }
});

app.post('/auth', async (req, res) => {
    const { code } = req.body;
    const {client_id,client_secret } = access_token_params;
    try {
        const response = await axios.post('https://github.com/login/oauth/access_token', null, {
            params: {
                client_id,
                client_secret,
                code,
            },
            headers: {
                Accept: 'application/json'
            },
            timeout: 60 * 1000,
        });

        const access_token = response.data?.access_token;
        if (!access_token) {
            res.status(200).send(false);
            return;
        }
        // 第二步：使用 access_token 获取用户信息
        const userResponse = await axios.get('https://api.github.com/user', {
            headers: {
                Authorization: `Bearer ${access_token}`
            }
        });

        const { id: githubUserId } = userResponse.data;
        if (!githubUserId) {
            res.status(200).send(false);
            return;
        }
        // 查找是否有该 githubUserId 的记录
        const { User } = db;
        let user = await User.findOne({ where: { githubUserId } });
        if (!user) {
            const role = githubUserId === myGithubId ? 'admin' : 'user'; // 判断角色
            user = await User.create({ githubUserId, role }); // 创建用户时指定角色
        }
        // 登录成功
        // 生成 JWT
        const token = jwt.sign({
            createdAt: Date.now(),
            userId: githubUserId,
        }, SECRET_KEY, { expiresIn: '24h' }); // 24小时过期
        // 可选择将 token 存储在 cookie 中
        res.cookie(AUTH_TOKEN, token, {
            httpOnly: true, // 仅通过 HTTP 协议访问
            secure: true,   // 仅在 HTTPS 上使用
            sameSite: 'None', // 允许跨站请求
            path: '/',// 设置 cookie 的路径为根路径
            domain: "."+paras["domain"],// 在子域名下共享
            maxAge: 24 * 60 * 60 * 1000, // cookie 有效期为 24 小时
        });
        logger.info("已生成博客网站的token: "+token);
        res.status(200).send({
            id:githubUserId
        });
    } catch (error) {
        logger.error(error);
        res.status(500).send("已超时");
    }
});

app.get('/logout',  AUTH_ENABLED ? logoutMiddleware : (req, res, next) => next(), async (req, res) => {
    try {
        res.cookie(AUTH_TOKEN, '', {
            httpOnly: true,    // 确保是 httpOnly
            secure: true,      // 如果是 secure cookie，确保使用 https
            sameSite: 'None',  // 与设置时相同
            path: '/',         // 确保与创建时的 path 相同
            domain: paras["domain"], // 与创建时的 domain 相同
            expires: new Date(0),  // 设置过期时间为过去的时间
        });
        logger.info("用户成功注销")
        // 如果删除成功，可以进行其他操作，如响应客户端
        res.status(200).send({ message: 'Cookie deleted successfully' });

    } catch (error) {
        // 处理异常
        console.error('删除 cookie 时发生错误:', error);
        logger.info("用户注销失败")
        // 响应客户端错误
        res.status(500).send({ error: 'Failed to delete cookie' });
    }
})

// 图片上传
// 设置上传目录
const uploadDir = "blogImgs";
// 创建 multer 实例
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        try {
            // 检查目录是否存在，不存在则创建
            await fs_extra.ensureDir(uploadDir);
            cb(null, uploadDir);
        } catch (error) {
            cb(error);
        }
    },
    filename: (req, file, cb) => {
        // 使用摘要算法生成文件名
        const hash = crypto.createHash('sha256').update(Date.now() + file.originalname).digest('hex');
        const ext = path.extname(file.originalname); // 获取文件后缀
        const newFileName = `${hash}${ext}`; // 生成新的文件名，保持后缀
        cb(null, newFileName);
    }
});

// 设置 multer 中间件
const upload = multer({ storage });

// 图片上传路由
app.post('/blog/img/upload', (AUTH_ENABLED ? [authMiddleware, upload.single('editormd-image-file')] : upload.single('editormd-image-file')),
    async (req, res) => {
    // req.file 将包含上传的文件信息
    try {
        logger.info('Uploaded file:', req.file); // 打印文件信息
        if (req.file) {
            const filePath = `${req.protocol}://${req.get('host')}/blogImgs/${req.file.filename}`; // 生成完整的文件路径
            res.json({
                success: 1, // 上传成功
                message: '图片上传成功',
                url: filePath // 返回图片地址
            });
        } else {
            res.status(400).json({
                success: 0, // 上传失败
                message: '图片上传失败'
            });
        }
    }
    catch (error) {
        logger.error(error); // 打印错误信息到控制台
        res.status(500).json({
            success: 0,
            message: '服务器内部错误',
            error: error.message // 可以根据需要返回更多错误信息
        });
    }
});

// 静态文件服务，提供访问上传的图片
app.use('/blogImgs', express.static(uploadDir));


// 获取系统资源信息
// 创建 WebSocket 服务器
const wss = new WebSocketServer({ noServer: true });
// 定义定时推送函数
// 获取系统资源信息的函数
const getSystemStats = async () => {
    try {
      const cpu = await si.currentLoad();
      const memory = await si.mem();
      const fsData = await si.fsSize();  // 获取文件系统信息，包括多个磁盘

      // 合并所有磁盘的使用情况
      let totalSize = 0;   // 总磁盘容量
      let totalUsed = 0;   // 已用磁盘容量
      let totalDiskUsage = 0;  // 磁盘占用率加权总和
      let totalDiskCount = 0;  // 磁盘数量（用于加权计算占用率）

      fsData.forEach(disk => {
        totalSize += disk.size;
        totalUsed += disk.used;
        totalDiskUsage += (disk.used / disk.size) * 100 * disk.size;  // 加权占用率
        totalDiskCount += disk.size;
      });

      // 计算总磁盘占用率（加权平均）
      const weightedDiskUsage = totalDiskUsage / totalSize;

      // 格式化并返回系统资源统计信息
      return {
        cpuUsage: cpu.currentLoad.toFixed(2), // CPU 占用率（%）
        memoryUsage: ((memory.active / memory.total) * 100).toFixed(2), // 内存占用率（%）
        totalMemory: (memory.total / (1024 ** 3)).toFixed(2), // 总内存（GB）
        diskUsage: weightedDiskUsage.toFixed(2), // 磁盘占用率（%）
        totalDisk: (totalSize / (1024 ** 3)).toFixed(2), // 总磁盘量（GB）
      };
    } catch (error) {
      console.error('Error retrieving system stats', error);
      return null;
    }
};
// 定义定时推送函数
const sendSystemStats = async (ws) => {
    const stats = await getSystemStats();
    if (stats && ws.readyState === ws.OPEN) {
      ws.send(JSON.stringify(stats)); // 发送系统统计信息
    }
};

// 定时每5秒推送一次系统信息
setInterval(() => {
    getSystemStats();
    wss.clients.forEach((client) => {
      if (client.readyState === client.OPEN) {
        sendSystemStats(client);
      }
    });
}, 5000);

// 升级 HTTP 服务器到 WebSocket 服务器
server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit('connection', ws, request);
    });
});

// 启动 Express 服务器
server.listen(port, () => {
    logger.info(`server is listening on port: ${port}`);
});

// ////////////////////////////grpc
// app.js
import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';

const GRPC_PORT = 50051;

// 加载 proto 文件
const packageDefinition = protoLoader.loadSync('auth.proto', {});
const authProto = grpc.loadPackageDefinition(packageDefinition).auth;

// 实现 gRPC verifyToken 函数
const verifyToken = async (call, callback) => {
    const token = call.request.token;
    logger.info("正在验证token["+token+']');
    try {
        const result = await isTokenValid(token);
        if (result.valid) {
            const userId = result.userId;
            callback(null, {
                valid: true,
                userId,
            });
        } else {
            callback(null, {
                valid: false,
                userId,
            });
        }
    } catch (error) {
        callback(null, {
            valid: false,
            userId:null
       })
    }
};

// 启动 gRPC 服务器
const grpcServer = new grpc.Server();
grpcServer.addService(authProto.AuthService.service, { verifyToken });
grpcServer.bindAsync(`0.0.0.0:${GRPC_PORT}`,
    grpc.ServerCredentials.createInsecure(),
    (err, port) => {
        if (err) {
          logger.error('Failed to bind server:', err);
          return;
        }
        logger.info(`grpc server is listening on port:${port}`);
    }
);

